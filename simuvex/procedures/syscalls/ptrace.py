import simuvex
import logging

######################################
# ptrace
######################################

l = logging.getLogger("simuvex.procedures.syscall")

class ptrace(simuvex.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument

    IS_SYSCALL = True

    def run(self, request, pid, addr, data):
        if self.state.se.symbolic(request):
            l.warning("Symbolic PTRACE_* request, returning unconstrained value")
            res = self.state.se.BVS('ptrace_return', self.state.arch.bits)

        else:
            request_concrete = self.state.se.any_int(request)
            # PTRACE_TRACEME
            if request_concrete == 0:
                # process is already traced
                if 'ptrace_istraced' in self.state.procedure_data.global_variables and self.state.procedure_data.global_variables['ptrace_istraced']:
                    res = self.state.se.BVV(-1, self.state.arch.bits)

                else:
                    self.state.procedure_data.global_variables['ptrace_istraced'] = True
                    res = self.state.se.BVV(0, self.state.arch.bits)

            else:
                l.error("Unimplemented PTRACE_* request(#%d), returning unconstrained value", request_concrete)
                res = self.state.se.BVS('ptrace_return', self.state.arch.bits)
        return res
