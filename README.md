Firewall
========

An Ansible Role that configures the host's firewall on Debian / Ubuntu.

The role allows three level of rules definition and overriding. You can change the rules for specific hosts and groups instead of re-defining everything.

* `firewall_ipv4_rules_default`: Here you can define general configurations.
* `firewall_ipv4_rules_group`: Here you can override or add rules by group.
* `firewall_ipv4_rules_host`: Here you can override or add rules by host.

The same logic works for IPv6 rules with the variables `firewall_ipv6_rules_default`, `firewall_ipv6_rules_group` and `firewall_ipv6_rules_host`.

This role also ensures the creation of custom chains that are used on the defined rules. You can create other chains using the available variables `firewall_ipv4_chains_default`, `firewall_ipv4_chains_group`, `firewall_ipv4_chains_host`, `firewall_ipv6_chains_default`, `firewall_ipv6_chains_group` and `firewall_ipv6_chains_host`.

Currently the role uses `iptables` as firewall backend, but it should be easy to use another one.

For more information about how `iptables` works, you could read the [Arch Linux iptables guide](https://wiki.archlinux.org/index.php/iptables). Also there is a complete guide about [rule targets](http://www.iptables.info/en/iptables-targets-and-jumps.html).

Requirements
------------

None.

Role Variables
--------------

Available variables are listed below, along with default values (see `defaults/main.yml`):

    firewall_ipv4_configure: True

Enable the configuration of the firewall for IPv4 connections.

    firewall_ipv6_configure: False

Enable the configuration of the firewall for IPv6 connections.

All the following variables applies to the IPv4 or IPv6 firewall, based on they prefix.

    firewall_ipv4_rules_flush: True
    firewall_ipv6_rules_flush: True

Flush all existing rules and chains.

    firewall_ipv4_default_allow_input: False
    firewall_ipv6_default_allow_input: False

Allow connections as default input policy.

    firewall_ipv4_default_allow_forward: False
    firewall_ipv6_default_allow_forward: False

Allow connections as default forward policy.

    firewall_ipv4_default_allow_output: True
    firewall_ipv6_default_allow_output: True

Allow connections as default output policy.

    firewall_ipv4_input_disallow_invalid: True
    firewall_ipv6_input_disallow_invalid: True

Disallow incoming connections with invalid state.

    firewall_ipv4_input_allow_localhost: True
    firewall_ipv6_input_allow_localhost: True

Allow incoming connections to localhost.

    firewall_ipv4_input_allow_icmp_ping: False
    firewall_ipv6_input_allow_icmp_ping: False

Allow incoming ping requests.

    firewall_ipv4_input_allow_established: True
    firewall_ipv6_input_allow_established: True

Allow incoming connections with an established or related state.

    firewall_ipv4_input_log_disallowed: True
    firewall_ipv6_input_log_disallowed: True

Log all the incoming connections that does not match any rule.

    firewall_ipv4_forward_allow_established: False
    firewall_ipv6_forward_allow_established: False

Allow forwarding connections with an established or related state.

    firewall_ipv4_output_allow_localhost: True
    firewall_ipv6_output_allow_localhost: True

Allow incoming connections from localhost.

    firewall_ipv4_output_allow_icmp_ping: False
    firewall_ipv6_output_allow_icmp_ping: False

Allow outgoing ping responses.

    firewall_ipv4_output_disallow_icmp_redirect: True
    firewall_ipv6_output_disallow_icmp_redirect: True

Disallow outgoing ICMP redirect responses.

    firewall_ipv4_nat_prerouting_allow_established: False
    firewall_ipv6_nat_prerouting_allow_established: False

Allow prerouting incoming connections with an established or related state.

    firewall_ipv4_nat_postrouting_allow_established: False
    firewall_ipv6_nat_postrouting_allow_established: False

Allow postrouting outgoing connections with an established or related state.

    firewall_ipv4_chains_default:
      - name: custom_chain
        table: filter
    firewall_ipv6_chains_default:
      - name: custom_chain
        table: filter

Custom chains that should be created. General configuration.

    firewall_ipv4_chains_group:
      - name: custom_chain
        table: filter
    firewall_ipv6_chains_group:
      - name: custom_chain
        table: filter

Custom chains that should be created. Group level configuration.

    firewall_ipv4_chains_host:
      - name: custom_chain
        table: filter
    firewall_ipv6_chains_host:
      - name: custom_chain
        table: filter

Custom chains that should be created. Host level configuration.

    firewall_ipv4_rules_default: []
    firewall_ipv6_rules_default: []
    firewall_ipv4_rules_group: []
    firewall_ipv6_rules_group: []
    firewall_ipv4_rules_host: []
    firewall_ipv6_rules_host: []

The role allows three level of rules definition and overriding. You can change the rules for specific hosts and groups instead of re-defining everything.

Each variable is a list of dictionaries, which should have the structure showed below. Each `group` could be overrided of complemented by the other variables, based on the `replace` value.

`rules` is the list of rules that should be applied to the firewall. All the conditions for the packet are optional and only one target will be used if multiple are defined as True (If none, the packet will be accepted).

    firewall_ipv4_rules_group:
      - group: Name of the rule group
        replace: False
        rules:
          - table: filter
            chain: input
            interface_in: eth0
            interface_out: eth0
            protocol: tcp
            icmp_type: echo-request
            source: 0.0.0.0/0
            sources:
              - 127.0.0.1
              - 192.168.1.1
            source_port: 2048
            source_ports:
              - 2000
              - 2001
            destination: 0.0.0.0/0
            destinations:
              - 127.0.0.1
              - 192.168.1.1
            destination_port: 22
            destination_ports:
              - 80
              - 443
            state_new: True
            limit: 5/m
            limit_burst: 10
            target_accept: True
            target_custom: custom_chain
            target_dnat: False
            target_dnat_destination: 192.168.10.1
            target_drop: False
            target_log: False
            target_log_ip_options: False
            target_log_level: debug
            target_log_prefix: INPUT packets
            target_log_tcp_options: False
            target_log_tcp_sequence: False
            target_masquerade: False
            target_masquerade_ports: 1000-1500
            target_queue: False
            target_redirect: False
            target_redirect_ports: 1000-1500
            target_reject: False
            target_reject_with: icmp-host-prohibited
            target_return: False
            target_snat: False
            target_snat_source: 192.168.10.1
            target_ulog: False
            target_ulog_cprange: 100
            target_ulog_nlgroup: 2
            target_ulog_prefix: SSH connection attempt
            target_ulog_qthreshold: 10
            comment: OpenSSH 22/tcp

* `table`: Table for the rule. `filter`, `nat`, `filter`, `mangle`, etc. Default: `filter`.
* `chain`: Chain where the rule will be evaluated. `input`, `output`, `postrouting`, custom chain.
* `interface_in`: Match rule against the network interface through which the packet arrives.
* `interface_out`: Match rule against the network interface through which the packet exists the host.
* `protocol`: Match the protocol of the packet.
* `icmp_type`: Match the ICMP type, when using ICMP protocol.
* `source`: Match the IP address of the source of the packet.
* `sources`: Match the IP address of the source of the packet against multiple values.
* `source_port`: Match the source port of the packet.
* `source_ports`: Match the source port of the packet against multiple values.
* `destination`: Match the IP address of the destination of the packet.
* `destinations`: Match the IP address of the destination of the packet against multiple values.
* `destination_port`: Match the destination port of the packet.
* `destination_ports`: Match the destination port of the packet against multiple values.
* `state_new`: Match the state of the packet. It should be NEW.
* `limit`: When using the LOG target, limit the matching rate of the rule.
* `limit_burst`: When using the LOG target, maximum initial number of packets to match against the rule.
* `target_accept`: Jump to the ACCEPT target. Let's the packet pass through the chain.
* `target_custom`: Jump to a custom chain.
* `target_dnat`: Jump to the DNAT target. This rewrites the Destination IP address of a packet.
* `target_dnat_destination`: Tells the DNAT mechanism which Destination IP to set in the IP header.
* `target_drop`: Jump to the DROP target. Don't let the packet pass through the chain.
* `target_log`: Jump to the LOG target. Log the packet information to the system syslog.
* `target_log_ip_options`: This option will log most of the IP packet header options.
* `target_log_level`: Tell iptables and syslog which log level to use.
* `target_log_prefix`: Tells iptables to prefix all log messages with a specific prefix.
* `target_log_tcp_options`: This option logs the different options from the TCP packet headers.
* `target_log_tcp_sequence`: This option will log the TCP Sequence numbers, together with the log message.
* `target_masquerade`: The MASQUERADE target is used basically the same as the SNAT target, but it does not require any source option.
* `target_masquerade_ports`: This option is used to set the source port or ports to use on outgoing packets.
* `target_queue`: The QUEUE target is used to queue packets to User-land programs and applications.
* `target_redirect`: The REDIRECT target is used to redirect packets and streams to the machine itself.
* `target_redirect_ports`: This option specifies the destination port, or port range, to use.
* `target_reject`: The REJECT target works basically the same as the DROP target, but it also sends back an error message to the host sending the packet that was blocked.
* `target_reject_with`: This option tells the REJECT target what response to send to the host that sent the packet that we are rejecting.
* `target_return`: The RETURN target will cause the current packet to stop traveling through the chain where it hit the rule. If it is the subchain of another chain, the packet will continue to travel through the superior chains as if nothing had happened. If the chain is the main chain, for example the INPUT chain, the packet will have the default policy taken on it.
* `target_snat`: The SNAT target is used to do Source Network Address Translation, which means that this target will rewrite the Source IP address in the IP header of the packet.
* `target_snat_source`: This option is used to specify which source the packet should use.
* `target_ulog`: The ULOG target is used to provide user-space logging of matching packets. If a packet is matched and the ULOG target is set, the packet information is multicasted together with the whole packet through a netlink socket.
* `target_ulog_cprange`: This option tells the ULOG target how many bytes of the packet to send to the user-space daemon of ULOG.
* `target_ulog_nlgroup`: This option tells the ULOG target which netlink group to send the packet to.
* `target_ulog_prefix`: This option works just the same as the prefix value for the standard LOG target.
* `target_ulog_qthreshold`: This option tells the ULOG target how many packets to queue inside the kernel before actually sending the data to user-space.
* `comment`: Comment for the rule.

Dependencies
------------

None.

Example Playbook
----------------

    - hosts: servers
      vars_files:
        - vars/main.yml
      roles:
         - gcoop-libre.firewall

*Inside `vars/main.yml`*:

    firewall_ipv4_rules_flush: True
    firewall_ipv4_default_allow_input: False
    firewall_ipv4_default_allow_forward: False
    firewall_ipv4_default_allow_output: True
    firewall_ipv4_rules_default:
      - group: Allow SSH
        rules:
          - chain: input
            protocol: tcp
            destination_port: 22
            target_accept: True
    firewall_ipv4_rules_group:
      - group: Allow SSH
        replace: True
        rules:
          - chain: input
            protocol: tcp
            source: 192.168.10.1
            destination_port: 22
            target_accept: True

License
-------

GPLv2

Author Information
------------------

This role was created in 2017 by [gcoop Cooperativa de Software Libre](https://www.gcoop.coop).
