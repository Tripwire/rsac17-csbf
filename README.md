# Common Security Bulletin Format (CSBF)

## Description 
The goal of the Common Security Bulletin Format (CSBF) is to provide a uniform method of delivering security and patch related information. While we have standards for machine readable data ([OVAL](https://oval.mitre.org/) and [CVRF](http://www.icasi.org/cvrf/), we have no standardization of human-readable documentation. CSBF aims to provide this standard with clear, concise security information. While much of this standard shares similarities with various vendors, the goal is commonality across the vendors and to ensure the missing pieces of information are provided. 

## Format
A bulletin utilizing CSBF will consist of two main sections. The first is a generic section that covers the details specific to the bulletin, while the second will occur on a per vulnerability basis, providing details for each vulnerability referenced. 

### Bulletin Specific Information
This section will include the bulletin identifier and title. Also at the top of each bulletin will be reference links related to available OVAL and CVRF details as well as any XLS or CSV data feeds. Following this, will be the *Generic Bulletin Description*. This will clearly detail the affected component, products, and risks in plaintext. The description is followed by the *Affected Software Table*, one of the defining aspects of the CSBF. While most vendors tend to only list supported software in their affected software tables, the CSBF requires that all vulnerable software be referenced. The table will contain affected software on the Y-Axis and versions on the X-Axis. 

**Affected Software Table Requirements**
When colour is available, the table will be formatted using the following colour code:
- White - Invalid (This denotes invalid software versions (e.g. Server 2008 Release) aka software that do not exist).
- Green - Not Vulnerable
- Red - Vulnerable, No Patch Available
- Red w/ Patch Link - Vulnerable, Patch Available

When colour is not available and plain-text support is required, the fields will be marked using the following codes:
- I - Invalid
- NV - Not Vulnerable
- V - Vulnerable, No Patch Available
- V w/ Patch Link - Vulnerable, Patch Available

A bulletin may reference multiple patches for a platform and CSBF allows for two methods of handling multiple patches. Multiple patch links may be provided in the *Affected Software Table* or the text 'See Below' can be included with specific download links made available in the vulnerability detail section. 

Following the *Affected Software Table* will be the *Included CVEs* section, which will provide links to the specific vulnerability detail sections and act as the master list of all vulnerabilities included in the bulletin. Should a CVE not be available, the following values are acceptable:
- CVE-Pending-# - For vulnerabilities awaiting CVE assignment, numbers increase sequentially throughout the bulletin. 
- CVE-Denied-# - For CVE assignments that have been denied but for which a bulletin is still required. 

The final section of the bulletin specific information is *Other Industry Identifiers*, this is where you will find links to other industry documentation. This could be Bugtraq IDs, Vendor KBs, or any other relevant information. 

### Vulnerability Specific Details
This section, which will appear once for each vulnerability, contains vulnerability specific information. Each vulnerability will be titled by CVE (linked to [NVD](https://nvd.nist.gov/)) and, if required, a link to the CVRF document for the specific vulnerability. This will be followed with a vulnerability description, workarounds (optional), and mitigations (optional).

The next section will be the *Affected Software Table*, which follows the format from the generic bulletin section but with data specific to the individual vulnerability. If multiple patches are required, links to each patch must be included. Following the *Affected Software Table* will be the *Post Patch Configuration* section (optional), this is where any additional steps that the user must perform will be listed. 

Finally, each vulnerability is wrapped up with Related Links (optional) that reference blog posts, advisories, or other published documentation on the vulnerability and the acknowledgements section. 

## Usage
Usage of this bulletin format is open to all and we invite all vendors to adopt this as a standard for delivering human readable vulnerability information. 

## Credits
This standard was developed by Tyler Reguly (treguly@tripwire.com) and Lane Thames (lthames@tripwire.com) of [Tripwire](https://www.tripwire.com) as a result of our research into [Patch Fatigue](https://www.tripwire.com/register/combating-patch-fatigue-is-it-overwhelmed-to-the-detriment-of-enterprise-security/).
