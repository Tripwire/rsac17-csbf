###############################################################################
# 
# Copyright (c) 2017, Tripwire, Inc.
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###############################################################################

#############################################################
# Common Security Bulletin Format [CSBF] Generator          #
# Written by Tyler Reguly (treguly@tripwire.com)            #
#############################################################

# IMPORTS

import collections
import re


class CSBF(object):
    
    def __init__(self):
        self.__affected_software = collections.OrderedDict()
        self.__software_versions = collections.OrderedDict()
        self.__affected_software_versions = collections.OrderedDict()
        self.__cves_denied = 0
        self.__cves_pending = 0
        self.__description = ''
        
    
    def format(self):
        pass
        
    def table_edge(self, row_width, column_widths):
        result = '+'
        result += '-' * row_width
        result += '+'
        for value in column_widths:
            result += '-' * value
            result += '+'
        return result
    
    def cell_format(self, cell_value, cell_width):
        result = '+' 
        whitespace = cell_width - len(cell_value)
        half_whitespace = whitespace / 2
        result += ' ' * half_whitespace
        result += cell_value
        result += ' ' * half_whitespace
        if whitespace % 2 != 0:
            result += ' '
        return result
            
    @property
    def affected_software(self):
        self.label_affected_software
        results = 'Affected Software Table\n'
        rows = len(self.__affected_software.keys())
        if rows == 0:
            results += 'Affected Software not currently available\n'
            return results
        row_width = len(max(self.__affected_software.keys(), key=len)) + 2
        columns = len(max(self.__affected_software.values(), key=len))
        column_widths = []
        for i in range(columns):
            column_list = [self.__affected_software[curr_row][i] for curr_row in self.__affected_software.keys()]
            column_widths.append( len(max(column_list, key=len)) + 2 )
        for row in self.__affected_software.keys():
            results += self.table_edge(row_width, column_widths)
            results += '\n'
            results += self.cell_format(row, row_width)
            for i in range(columns):
                results += self.cell_format(self.__affected_software[row][i], column_widths[i])
            results += '+\n'
        results += self.table_edge(row_width, column_widths)
        results += '\n\n'
        return results
    
    def label_affected_software(self):
        if not self.__affected_software:
            all_software_versions = []
            for key in self.software_versions.keys():
                all_software_versions += self.software_versions[key]
            all_software_versions = list(set(all_software_versions))
            self.__affected_software['Versions'] = all_software_versions
        for software in self.affected_software_versions.keys():
            self.__affected_software[software] = []
            for val in self.__affected_software['Versions']:
                if val not in self.software_versions[software]:
                    self.__affected_software[software].append('I')
                elif val in self.software_versions[software] and val not in self.affected_software_versions[software]:
                    self.__affected_software[software].append('NV')
                else:
                    self.__affected_software[software].append('V')
            
        
    @property
    def affected_software_versions(self):
        return self.__affected_software_versions
    
    @affected_software_versions.setter
    def affected_software_versions(self, value):
        k, v = value
        try:
            if k not in self.__software_versions.keys():
                raise LookupError
        except LookupError as err:
            err.message = 'Affected Software not defined in Software Version'
            raise
        self.__affected_software_versions[k] = v
        
    @property
    def software_versions(self):
        return self.__software_versions
    
    @software_versions.setter
    def software_versions(self, value):
        k, v = value
        self.__software_versions[k] = v
        
    @property
    def description(self):
        results = 'Description\n'
        results += self.__description
        return results
    
    @description.setter
    def description(self, value):
        if isinstance(value, list):
            for k, v in value:
                self.__description += '%s\n%s\n' % (k, v)
        elif isinstance(value, tuple):
            self.__description += '%s\n%s\n' % (value)
        else:        
            self.__description += '%s\n' % (value)
            
            
        
class CSBFBulletin(CSBF):
    def __init__(self):
        super(CSBFBulletin, self).__init__()
        self.__bulletin_id = ''
        self.__bulletin_title = ''
        self.__cves = []
        self.__industry_ids = []

        
    
    @property
    def bulletin_id(self):
        return self.__bulletin_id
    
    @bulletin_id.setter
    def bulletin_id(self, value):
        self.__bulletin_id = value
        
    @property
    def bulletin_title(self):
        return self.__bulletin_title
    
    @bulletin_title.setter
    def bulletin_title(self, value):
        self.__bulletin_title = value
        
    @property
    def cves(self):
        results = 'CVEs\n'
        for cve in self.__cves:
            results += '%s\n' % (cve)
        return results
    
    @cves.setter
    def cves(self, value):
        if isinstance(value, list):
            for item in value:
                self.sort_cve(item)
        else:
            self.sort_cve(value)
            
    def sort_cve(self, value):
        cve = value.upper()
        if not cve.startswith('CVE-'):
            cve = 'CVE-' + cve
        if re.match('CVE-\d{4}-\d*$', cve):
            self.__cves.append(cve)
        elif cve == 'CVE-Pending':
            self.__cves_pending += 1
            self.__cves.append('%s-%d' % (cve, self.__cves_pending))
        elif cve == 'CVE-Denied':
            self.__cves_denied += 1
            self.__cves.append('%s-%d' % (cve, self.__cves_denied))
        else:
            try:
                raise ValueError
            except ValueError, err:
                err.message = 'Invalid CVE ID'
                raise
        
            
    @property
    def industry_ids(self):
        results = 'Other Industry Identifiers\n'
        if len(self.__industry_ids) == 0:
            results += 'No other industry identifiers are available at this time.'
        else:
            for name, url in self.__industry_ids:
                results += '%s [%s]\n' % (name, url)
        return results
    
    @industry_ids.setter
    def industry_ids(self, value):
        if isinstance(value, tuple):
            name, url = value
            self.__industry_ids.append((name, url))
    
    @property
    def report(self):
        print self.bulletin_id
        print self.bulletin_title
        print self.description
        print self.affected_software
        print self.cves
        print self.industry_ids
        print '\n'
        
    
class CSBFVuln(CSBF):
    def __init__(self):
        super(CSBFVuln, self).__init__()
        self.__cve = ''
        self.__cvrf_url = ''
        self.__nvd_url = ''
        self.__workaround = ''
        self.__mitigation = ''
        self.__post_patch_config = ''
        self.__related_links = []
        self.__acknowledgement = []
        
    @property
    def cve(self):
        return '%s [%s]\n' % (self.__cve, self.__nvd_url)
        
    
    @cve.setter
    def cve(self, value):
        cve = value.upper()
        if not cve.startswith('CVE-'):
            cve = 'CVE-' + cve
        if re.match('CVE-\d{4}-\d*$', cve):
            self.__cve = cve
        elif cve == 'CVE-Pending':
            self.__cve_pending += 1
            self.__cve = '%s-%d' % (cve, self.__cves_pending)
        elif cve == 'CVE-Denied':
            self.__cves_denied += 1
            self.__cve = '%s-%d' % (cve, self.__cves_denied)
        else:
            try:
                raise ValueError
            except ValueError, err:
                err.message = 'Invalid CVE ID'
                raise
        self.__nvd_url = 'https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s' % (value)
    
    @property
    def cvrf(self):
        results = ''
        if self.__cvrf_url:
            results += 'CVRF: %s\n\n' % (self.__cvrf_url)
        return results
            
    @cvrf.setter
    def cvrf(self, value):
        self.__cvrf_url = value
        
    @property
    def workaround(self):
        results = ''
        if self.__workaround:
            results += 'Workaround\n'
            results += self.__workaround
        return results
    
    @workaround.setter
    def workaround(self, value):
        self.__workaround = value
        
    @property
    def mitigation(self):
        results = ''
        if self.__mitigation:
            results += 'Mitigation\n'
            results += self.__mitigation
        return results
    
    @mitigation.setter
    def mitigation(self, value):
        self.__mitigation = value
        
    @property
    def post_patch_config(self):
        results = ''
        if self.__post_patch_config:
            results += 'Post Patch Configuration\n'
            results += self.__post_patch_config
        return results
    
    @post_patch_config.setter
    def post_patch_config(self, value):
        self.__post_patch_config = value
        
    @property
    def related_links(self):
        results = 'Related Links\n'
        if len(self.__related_links) == 0:
            results += 'No articles have been published regarding this vulnerability at this time.'
        else:
            for name, url in self.__related_links:
                results += '%s [%s]\n' % (name, url)
        return results
    
    @related_links.setter
    def related_links(self, value):
        name, url = value
        self.__related_links.append((name, url))
        
    @property
    def acknowledgement(self):
        results = ''
        if self.__acknowledgement:
            for vendor, name in self.__acknowledgement:
                results += '%s would like to thank %s for reporting %s.' % (vendor, name, self.__cve)
        return results
    
    @acknowledgement.setter
    def acknowledgement(self, value):
        if isinstance(value, list):
            for ack in value:
                self.__acknowledgement.append(ack)
        else:
            self.__acknowledgement.append(value)

    @property
    def report(self):
        print self.cve
        print self.cvrf
        print self.description
        print self.mitigation
        print self.workaround
        print self.affected_software
        print self.post_patch_config
        print self.related_links
        print self.acknowledgement
        print '\n'


