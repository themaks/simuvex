import simuvex

class ptrace(simuvex.SimProcedure):
    def run(self, request, pid, addr, data): #pylint:disable=arguments-differ,unused-argument

        return self.inline_call(simuvex.SimProcedures['syscalls']['ptrace'],
                                request,
                                pid,
                                addr,
                                data
                                ).ret_expr
