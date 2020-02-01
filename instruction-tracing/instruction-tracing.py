import idc
import idaapi
import idautils

PRE_ADDR = None


def clear():
    heads = idautils.Heads(idc.SegStart(idc.ScreenEA()), idc.SegEnd(idc.ScreenEA()))
    for i in heads:
        idc.SetColor(i, idc.CIC_ITEM, 0xFFFFFF)


def get_new_color(current_color):
    colors = [0xffe699, 0xffcc33, 0xe6ac00, 0xb38600]
    if current_color == 0xFFFFFF:
        return colors[0]
    if current_color in colors:
        pos = colors.index(current_color)
        if pos == len(colors) - 1:
            return colors[pos]
        else:
            return colors[pos + 1]
    return 0xFFFFFF


def tracing():
    global PRE_ADDR
    event = idc.GetDebuggerEvent(idc.WFNE_ANY, -1)
    if event <= 1:
        idc.RunTo(idc.BeginEA())
    idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)
    idc.EnableTracing(idc.TRACE_STEP, 1)
    idc.GetDebuggerEvent(idc.WFNE_ANY | idc.WFNE_CONT, -1)
    while True:
        event = idc.GetDebuggerEvent(idc.WFNE_ANY, -1)
        if event <= 1:
            break
        addr = idc.GetEventEa()
        print event, "==>", hex(addr)

        # judge breakpoint and same addr
        if PRE_ADDR != addr:
            PRE_ADDR = addr
        else:  # same addr
            if event == idc.BREAKPOINT:  # and now is breakpoint
                break

        current_color = idc.GetColor(addr, idc.CIC_ITEM)
        new_color = get_new_color(current_color)
        idc.SetColor(addr, idc.CIC_ITEM, new_color)


class InstructionTracing(idaapi.plugin_t):
    flags = 0
    wanted_name = "Instruction tracing"
    wanted_hotkey = "Ctrl+Shift+j"
    comment = "Coloring to each instruction executed"
    help = "Ctrl+Shift+j: Run \n Ctrl+Shift+k: Clean"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        clear()
        tracing()
        idaapi.add_hotkey("Ctrl+Shift+k", clear)


def PLUGIN_ENTRY():
    return InstructionTracing()

