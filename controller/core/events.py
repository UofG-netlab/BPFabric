_handlers = {}

def set_event_handler(opcode):
    def set_event_handler_decorator(func):
        _handlers.setdefault(opcode, []).append(func)
        return func
    return set_event_handler_decorator
