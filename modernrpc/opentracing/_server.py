"""Implementation of the service-side open-tracing interceptor."""

import sys
import logging
import re

from modernrpc.opentracing import ActiveSpanSource
from ._utilities import get_method_type, get_deadline_millis,\
    log_or_wrap_request_or_iterator, RpcInfo
import opentracing
from opentracing.ext import tags as ot_tags


class _OpenTracingServicerContext(ActiveSpanSource):

    def __init__(self, servicer_context, active_span):
        self._servicer_context = servicer_context
        self._active_span = active_span
        self.code = 200
        self.details = None

    def is_active(self, *args, **kwargs):
        return self._servicer_context.is_active(*args, **kwargs)

    def time_remaining(self, *args, **kwargs):
        return self._servicer_context.time_remaining(*args, **kwargs)

    def cancel(self, *args, **kwargs):
        return self._servicer_context.cancel(*args, **kwargs)

    def add_callback(self, *args, **kwargs):
        return self._servicer_context.add_callback(*args, **kwargs)

    def invocation_metadata(self, *args, **kwargs):
        return self._servicer_context.invocation_metadata(*args, **kwargs)

    def peer(self, *args, **kwargs):
        return self._servicer_context.peer(*args, **kwargs)

    def peer_identities(self, *args, **kwargs):
        return self._servicer_context.peer_identities(*args, **kwargs)

    def peer_identity_key(self, *args, **kwargs):
        return self._servicer_context.peer_identity_key(*args, **kwargs)

    def auth_context(self, *args, **kwargs):
        return self._servicer_context.auth_context(*args, **kwargs)

    def send_initial_metadata(self, *args, **kwargs):
        return self._servicer_context.send_initial_metadata(*args, **kwargs)

    def set_trailing_metadata(self, *args, **kwargs):
        return self._servicer_context.set_trailing_metadata(*args, **kwargs)

    def abort(self, *args, **kwargs):
        if not hasattr(self._servicer_context, 'abort'):
            raise RuntimeError('abort() is not supported with the installed version of jsonrpcio')
        return self._servicer_context.abort(*args, **kwargs)

    def set_code(self, code):
        self.code = code
        return self._servicer_context.set_code(code)

    def set_details(self, details):
        self.details = details
        return self._servicer_context.set_details(details)

    def get_active_span(self):
        return self._active_span

# On the service-side, errors can be signaled either by exceptions or by calling
# `set_code` on the `servicer_context`. This function checks for the latter and
# updates the span accordingly.
def _check_error_code(span, servicer_context, rpc_info):
    if servicer_context.code != 200:
        span.set_tag('error', True)
        error_log = {'event': 'error', 'error.kind': str(servicer_context.code)}
        if servicer_context.details is not None:
            error_log['message'] = servicer_context.details
        span.log_kv(error_log)
        rpc_info.error = servicer_context.code


class OpenTracingServerInterceptor():

    def __init__(self, tracer, log_payloads, span_decorator):
        self._tracer = tracer
        self._log_payloads = log_payloads
        self._span_decorator = span_decorator

    def _start_span(self, header, method):
        span_context = None
        error = None
        try:
            if header:
                span_context = self._tracer.extract(
                    opentracing.Format.HTTP_HEADERS, header)
        except (opentracing.UnsupportedFormatException,
                opentracing.InvalidCarrierException,
                opentracing.SpanContextCorruptedException) as e:
            logging.exception('tracer.extract() failed')
            error = e
        tags = {
            ot_tags.COMPONENT: 'jsonrpc',
            ot_tags.SPAN_KIND: ot_tags.SPAN_KIND_RPC_SERVER
        }
        span = self._tracer.start_span(
            operation_name=method, child_of=span_context, tags=tags)
        if error is not None:
            span.log_kv({'event': 'error', 'error.object': error})
        return span

    def trace_before_call(self, func_name, args, kwargs, headers):
        with self._start_span(headers, func_name) as span:
            if self._log_payloads:
                span.log_kv({'func_name': func_name, 'args': args, 'kwargs': kwargs})

            return span

    def trace_after_call(self, response_text, span):
        if self._log_payloads:
            span.log_kv({'response': response_text})
