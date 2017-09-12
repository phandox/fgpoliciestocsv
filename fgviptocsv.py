#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of fgpoliciestocsv.
#
# Copyright (C) 2014, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# fgpoliciestocsv is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fgpoliciestocsv is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with fgpoliciestocsv.  If not, see <http://www.gnu.org/licenses/>.

import re
import os
import sys
import csv

# OptionParser imports
from optparse import OptionParser

# Options definition
option_0 = {'name': ('-i', '--input-file'), 'help': '<INPUT_FILE>: Fortigate configuration file. Ex: fgfw.cfg',
            'nargs': 1}
option_1 = {'name': ('-o', '--output-file'), 'help': '<OUTPUT_FILE>: output csv file (default \'./vip-out.csv\')',
            'default': 'vip-out.csv', 'nargs': 1}
option_2 = {'name': ('-n', '--newline'),
            'help': '<NEWLINE> : insert a newline between each address for better readability', 'action': 'store_true',
            'default': False}
option_3 = {'name': ('-s', '--skip-header'), 'help': '<SKIP_HEADER> : do not print the csv header',
            'action': 'store_true', 'default': False}
option_4 = {'name': ('-S', '--split-ip-subnet'),
            'help': '<SPLIT_IP_SUBNET> : put ip address and subnet mask in seperate fields', 'action': 'store_true',
            'default': False}

options = [option_0, option_1, option_2, option_3, option_4]

# Handful patterns
# -- Entering address definition block
p_entering_service_block = re.compile('^\s*config firewall vip$', re.IGNORECASE)

# -- Exiting address definition block
p_exiting_service_block = re.compile('^end$', re.IGNORECASE)

# -- Commiting the current address definition and going to the next one
p_service_next = re.compile('^next$', re.IGNORECASE)

# -- VIP name
p_service_name = re.compile('^\s*edit\s+"(?P<vip_name>.*)"$', re.IGNORECASE)

# -- VIP settings
p_service_setting = re.compile('^\s*set\s+(?P<vip_key>\S+)\s+(?P<vip_value>.*)$', re.IGNORECASE)


# def divide_subnet(subnet_field):
#     divide = subnet_field.split(' ')
#     return divide[0], divide[1]


# Functions
def parse(fd):
    """
        Parse the data according to several regexes

        @param fd:	input file descriptor
        @rtype:	return a list of addresses ( [ {'id' : '1', 'srcintf' : 'internal', ...}, {'id' : '2', 'srcintf' : 'external', ...}, ... ] )
                and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
    """
    global p_entering_service_block, p_exiting_service_block, p_service_next, p_service_name, p_service_setting

    in_vip_block = False

    address_list = []
    address_elem = {}

    order_keys = []

    with open(fd, 'rb') as fd_input:
        for line in fd_input:
            line = line.lstrip().rstrip().strip()

            # We match a VIP block
            if p_entering_vip_block.search(line):
                in_vip_block = True

            # We are in a VIP block
            if in_vip_block:
                if p_vip_name.search(line):
                    vip_name = p_vip_name.search(line).group('vip_name')
                    address_elem['name'] = vip_name
                    if not ('name' in order_keys): order_keys.append('name')

                # We match a setting
                if p_vip_setting.search(line):
                    vip_key = p_vip_setting.search(line).group('vip_key')
                    if not (vip_key in order_keys): order_keys.append(vip_key)
                    # if not ('ip_addr' in order_keys): order_keys.append('ip_addr')
                    # if not ('subnet_mask' in order_keys): order_keys.append('subnet_mask')

                    vip_value = p_vip_setting.search(line).group('vip_value').strip()
                    vip_value = re.sub('["]', '', vip_value)
                    # if vip_key == "subnet":
                    #     ip_addr, subnet_mask = divide_subnet(vip_value)
                    #     address_elem['ip_addr'] = ip_addr
                    #     address_elem["subnet_mask"] = subnet_mask

                    address_elem[vip_key] = vip_value

                # We are done with the current address id
                if p_vip_next.search(line):
                    address_list.append(address_elem)
                    address_elem = {}

            # We are exiting the address block
            if p_exiting_vip_block.search(line):
                in_vip_block = False

    return (address_list, order_keys)


def generate_csv(results, keys, fd, newline, skip_header):
    """
        Generate a plain ';' separated csv file

        @param fd : output file descriptor
    """
    if results and keys:
        with open(fd, 'wb') as fd_output:
            spamwriter = csv.writer(fd_output, delimiter=';')

            if not (skip_header):
                spamwriter.writerow(keys)

            for address in results:
                output_line = []

                for key in keys:
                    if key in address.keys():
                        output_line.append(address[key])
                    else:
                        output_line.append('')

                spamwriter.writerow(output_line)
                if newline: spamwriter.writerow('')

        fd_output.close()

    return


def main(options, arguments):
    """
        Dat main
    """
    if (options.input_file == None):
        parser.error('Please specify a valid input file')

    results, keys = parse(options.input_file)
    generate_csv(results, keys, options.output_file, options.newline, options.skip_header)

    return


if __name__ == "__main__":
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    main(options, arguments)
