# Copyright (c) 2005-2006 XenSource, Inc. All use and distribution of this 
# copyrighted material is governed by and subject to terms and conditions 
# as licensed by XenSource, Inc. All other rights reserved.
# Xen, XenSource and XenEnterprise are either registered trademarks or 
# trademarks of XenSource Inc. in the United States and/or other countries.

###
# XEN CLEAN INSTALLER
# TUI Network configuration screens
#
# written by Andrew Peace

import uicontroller
import netutil
import snackutil

from snack import *

def get_network_config(screen):
    answers = {}

    entries = [ 'Configure all interfaces using DHCP',
                'Specify a different network configuration' ]

    (button, entry) = ListboxChoiceWindow(
        screen,
        "Network Configuration",
        "How would you like networking to be configured on this host?",
        entries,
        ['Ok', 'Back'], width=50)

    if button == "ok" or button == None:
        # proceed to get_autoconfig_ifaces if manual configuration was selected:
        if entry == 1:
            (rv, config) = get_autoconfig_ifaces(screen)
            if rv == -1: return 0, config
            if rv == 1: return 1, config
        else:
            return 1, (True, None)
    
    if button == "back": return -1, None

def get_autoconfig_ifaces(screen):
    seq = []
    for x in netutil.getNetifList():
        seq.append((get_iface_configuration, (x, screen)))

    # when this was written this branch would never be taken
    # since we require at least one NIC at setup time:
    if len(seq) == 0:
        return (True, None)

    subdict = {}
    rv = uicontroller.runUISequence(seq, subdict)
    return rv, (False, subdict)
    
def get_iface_configuration(answers, iface, screen):
    def identify_interface(iface):
        ButtonChoiceWindow(screen,
                           "Identify Interface",
                           """Name: %s

MAC Address; %s

PCI details; %s""" % (iface, netutil.getHWAddr(iface), netutil.getPCIInfo(iface)),
                           ['Ok'], width=60)
    def enabled_change():
        for x in [ ip_field, gateway_field, subnet_field ]:
            x.setFlags(FLAG_DISABLED,
                           (enabled_cb.value() and not dhcp_cb.value()))
        dhcp_cb.setFlags(FLAG_DISABLED, enabled_cb.value())
    def dhcp_change():
        for x in [ ip_field, gateway_field, subnet_field ]:
            x.setFlags(FLAG_DISABLED,
                           (enabled_cb.value() and not dhcp_cb.value()))

    gf = GridFormHelp(screen, 'Network Configuration', None, 1, 5)
    text = TextboxReflowed(45, "Configuration for %s (%s)" % (iface, netutil.getHWAddr(iface)))
    buttons = ButtonBar(screen, [("Ok", "ok"), ("Back", "back"), ("Identify", "identify")])

    # note spaces exist to line checkboxes up:
    enabled_cb = Checkbox("Enable interface", 1)
    dhcp_cb = Checkbox("Configure with DHCP", 1)
    enabled_cb.setCallback(enabled_change, ())
    dhcp_cb.setCallback(dhcp_change, ())

    ip_field = Entry(16)
    ip_field.setFlags(FLAG_DISABLED, False)
    subnet_field = Entry(16)
    subnet_field.setFlags(FLAG_DISABLED, False)
    gateway_field = Entry(16)
    gateway_field.setFlags(FLAG_DISABLED, False)

    ip_text = Textbox(15, 1, "IP Address:")
    subnet_text = Textbox(15, 1, "Subnet mask:")
    gateway_text = Textbox(15, 1, "Gateway:")

    entry_grid = Grid(2, 3)
    entry_grid.setField(ip_text, 0, 0)
    entry_grid.setField(ip_field, 1, 0)
    entry_grid.setField(subnet_text, 0, 1)
    entry_grid.setField(subnet_field, 1, 1)
    entry_grid.setField(gateway_text, 0, 2)
    entry_grid.setField(gateway_field, 1, 2)

    gf.add(text, 0, 0, padding = (0,0,0,1))
    gf.add(enabled_cb, 0, 1, anchorLeft = True)
    gf.add(dhcp_cb, 0, 2, anchorLeft = True)
    gf.add(entry_grid, 0, 3, padding = (0,0,0,1))
    gf.add(buttons, 0, 4)

    while True:
        result = gf.run()
        # do we display a popup then continue, or leave the loop?
        if not buttons.buttonPressed(result) == 'ok' and \
           not buttons.buttonPressed(result) == 'back':
            assert buttons.buttonPressed(result) == 'identify'
            identify_interface(iface)
        else:
            # leave the loop - 'ok' or 'back' was pressed:
            screen.popWindow()
            break

    if buttons.buttonPressed(result) == 'ok':
        answers[iface] = {'use-dhcp': dhcp_cb.value(),
                          'enabled': enabled_cb.value(),
                          'ip': ip_field.value(),
                          'subnet-mask': subnet_field.value(),
                          'gateway': gateway_field.value() }
        return 1
    elif buttons.buttonPressed(result) == 'back':
        return -1