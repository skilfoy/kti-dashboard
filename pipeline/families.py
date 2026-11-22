#!/usr/bin/env python3
"""Product families: one deterministic taxonomy for every vulnerability row on the site.

Imported by build_data.py (the edge-device class of KEV and early-warning rows) and build_baserates.py (the weakness
base rates by product family). A CVE takes the first family whose rule matches, in FAMILIES order; the basis says which
signal decided it:
  edge rule        an EDGE_RULES pattern over vendor, product and title (the Edge-device lens on the Vulnerabilities page)
  vendor/product   a family pattern over vendor, product and title
  CNA              the CVE Numbering Authority that assigned the CVE (assignerShortName), for CNAs that cover one family
  registry         the record names a package registry (collectionURL or packageName in the CNA's affected list)
A CVE none of them matches is "Unclassified"; the base rates count it in no family and report how many there are.
Self-test: python3 -I pipeline/families.py --self-test
"""
import re
import sys

# ---------------------------------------------------------------- edge devices (unchanged from build_data.py, 3.13.1)
# Order matters: the first matching rule wins, so product-specific rules run before broad vendor rules
# (a Zyxel switch is a network device, a Cisco or Fortinet mail gateway is an email appliance).
EDGE_RULES = [
    ("Email / file-transfer appliance", r"barracuda|email security|secure email|email gateway|fortimail|\besa\b|moveit|goanywhere|cleo|accellion|fta\b|crushftp|wing ftp|serv-u|zimbra|exchange server|sharefile"),
    ("Remote-access gateway / ADC", r"ivanti connect secure|ivanti policy secure|pulse connect|pulse secure|netscaler|citrix adc|citrix gateway|big-ip|f5 |array networks|ivanti neurons for zero|endpoint manager mobile|epmm|mobileiron|ivanti sentry"),
    ("Remote management / support", r"screenconnect|connectwise|simplehelp|beyondtrust|remote support|privileged remote access|kaseya|n-able|take control|teamviewer|anydesk|ivanti endpoint manager\b|desktop central|endpoint central"),
    ("Router / network device", r"\bios xe\b|\bios xr\b|cisco ios|nx-os|mikrotik|routeros|d-link|tp-link|draytek|netgear|ubiquiti|edgerouter|junos|arcadyan|\bzte\b|huawei.*router|linksys|tenda|totolink|four-faith|cisco small business|rv\d{3}|sd-wan|velocloud|identity services engine|\bswitch(es)?\b|arubaos|aruba"),
    ("Firewall / VPN", r"fortios|fortigate|fortiproxy|fortiweb|fortimanager|fortianalyzer|fortiswitch|pan-os|globalprotect|palo alto|adaptive security appliance|\basa\b|firepower|secure firewall|sonicwall|sonicos|\bsma\b|check point|quantum security|watchguard|firebox|sophos firewall|xg firewall|zyxel|juniper srx"),
]
_EDGE = [(label, re.compile(rx)) for label, rx in EDGE_RULES]


def edge_class(vendor, product, name):
    t = f"{vendor} {product} {name}".lower()
    for label, rx in _EDGE:
        if rx.search(t):
            return label
    return ""


# ---------------------------------------------------------------- product families
# Each family: name, what it covers (shown on the page), CNAs that assign for that family alone, and a pattern over
# "vendor product" in lower case. The five edge classes come first; then families whose products are named
# unambiguously; operating systems and the broad enterprise family come late, so "Zoom Workplace for Windows" is a
# desktop application and "Docker Desktop" a container tool. When the record names no vendor or product, the patterns are
# tried on its title and the first 160 characters of its description (basis "title"). A CNA set decides only when no
# pattern matched.
EDGE = "Network edge"
SMALL_WEB = "Small web applications"
OSS = "Open-source projects and packages"
FAMILIES = [
    (SMALL_WEB, "PHP and web projects from code-sharing and tutorial sites (SourceCodester, code-projects, PHPGurukul, itsourcecode, CampCodes, Kashipara and similar) and the management-system projects VulDB reports in bulk",
     set(), r"sourcecodester|code-projects|code projects|phpgurukul|itsourcecode|campcodes|kashipara|projectworlds|1000projects|1000 projects|oretnom23|razormist|mayurik|janobe|carmelogarcia|code-astro|codeastro|anisha|projectsandprograms|codezips|source ?code ?& ?projects|fabianros|\bfabian\b"),
    ("WordPress plugins and themes", "WordPress core, plugins and themes",
     {"Wordfence", "Patchstack", "WPScan"}, r"wordpress|\bwp[ -]|woocommerce|elementor"),
    ("AI and machine learning software", "Model runtimes, agent frameworks, ML libraries and AI serving tools",
     set(), r"tensorflow|pytorch|\btorch\b|keras|\btransformers\b|hugging ?face|langchain|langgraph|llama[ -.]?cpp|llama_index|llamaindex|ollama|\bvllm\b|gradio|mlflow|comfyui|open[ -]?webui|anything-?llm|lollms|\bonnx|triton inference|anyscale|\bray\b|openclaw|autogpt|crewai|\bdify\b|flowise|langflow|litellm|text-generation-webui|stable[- ]diffusion|invokeai|model context protocol|\bmcp[ -]server|semantic kernel|haystack|chainlit|bentoml|kserve|kubeflow|jupyter|\bnemo\b|megatron|deepspeed|paddlepaddle|mindspore|xgboost|scikit|h2o|lobe-?chat|librechat|\bn8n\b|agentforce|copilot studio|bedrock agent"),
    ("Browsers", "Web browsers and their engines",
     {"Chrome"}, r"\bchrome\b|chromium|firefox|\bsafari\b|webkit|microsoft edge|internet explorer|\bopera\b|brave|vivaldi|samsung internet|flash player|silverlight"),
    ("Desktop and office applications", "Office suites, document readers, creative tools, mail, meeting and messaging clients",
     {"adobe", "Foxit", "autodesk"}, r"microsoft office|\boffice\b|microsoft 365 apps|microsoft word|\bexcel\b|powerpoint|outlook|visio|onenote|microsoft access|acrobat|adobe reader|pdf reader|foxit|photoshop|illustrator|indesign|premiere|after effects|lightroom|adobe bridge|adobe animate|adobe dimension|substance 3d|framemaker|libreoffice|openoffice|autocad|autodesk|revit|7-zip|winrar|notepad\+\+|thunderbird|zoom (client|workplace|meetings|rooms)|\bslack\b|microsoft teams|webex|telegram|whatsapp|signal desktop|discord|\bvlc\b|media player|irfanview|sketchup|evernote|obsidian|pdf-xchange|nitro pdf|\bplex\b|ashlar|keepass|1password|bitwarden"),
    ("Developer and CI/CD tools", "Source control, build and CI/CD servers, IDEs, artifact registries and developer tooling",
     {"jenkins", "GitLab", "JetBrains"}, r"jenkins|gitlab|github enterprise|\bgitea\b|\bgogs\b|bitbucket|bamboo|teamcity|jetbrains|intellij|pycharm|youtrack|artifactory|jfrog|sonatype|nexus repository|\bgit\b|\bsvn\b|subversion|visual studio|vs ?code|vscode|gradle|sonarqube|argo ?cd|tekton|spinnaker|circleci|buildkite|github actions|github copilot|cursor"),
    ("Virtualization, cloud and containers", "Hypervisors, cloud platforms, containers and orchestration",
     {"vmware"}, r"vmware|\besxi\b|vcenter|vsphere|hyper-v|\bxen\b|\bqemu\b|\bkvm\b|kubernetes|\bk8s\b|openshift|rancher|\bdocker\b|containerd|\brunc\b|\bpodman\b|\bhelm\b|istio|\benvoy\b|openstack|proxmox|nutanix|citrix hypervisor|xenserver|virtualbox|\bazure\b|\baws\b|amazon web services|google cloud|cloud foundry|terraform|hashicorp|\bvault\b|\bconsul\b"),
    ("Industrial and OT", "Industrial control systems, PLCs, SCADA and HMI software, building and energy automation",
     {"icscert", "siemens", "SICK AG", "Schneider", "ABB", "Mitsubishi", "Rockwell", "Honeywell", "Hitachi Energy", "Phoenix Contact", "WAGO", "CERTVDE", "Moxa", "Yokogawa", "Emerson", "OMRON"},
     r"siemens|simatic|sinec|scalance|schneider electric|modicon|ecostruxure|rockwell|allen-bradley|factorytalk|studio 5000|\babb\b|mitsubishi electric|melsec|honeywell|yokogawa|emerson|omron|delta electronics|\bmoxa\b|phoenix contact|\bwago\b|hitachi energy|ge vernova|ge digital|\bscada\b|\bplc\b|\bhmi\b|codesys|openplc|scadabr|inductive automation|kepware|aveva|wonderware|beckhoff|advantech|sick ag|festo|danfoss|eaton|johnson controls|metasys|niagara|tridium|carrier|bosch rexroth|pilz|weidmueller|keba"),
    ("IoT and peripheral devices", "Cameras, NAS, printers, smart-home, vehicle and consumer devices",
     set(), r"hikvision|dahua|\baxis\b|reolink|foscam|amcrest|uniview|camera|\bnvr\b|\bdvr\b|\bnas\b|qnap|synology|western digital|my cloud|asustor|terramaster|unraid|printer|laserjet|officejet|deskjet|lexmark|ricoh|xerox|konica|kyocera|\bepson\b|smart (home|tv|plug|lock|bulb)|tuya|philips hue|\broku\b|sonos|\biot\b|smartwatch|charger|charging|vehicle|automotive|infotainment|\bcar\b|tesla|garmin|fitbit|wyze|ring\b|eufy|anker"),
    ("Chipsets, firmware and drivers", "Processor, modem and GPU firmware and drivers, BIOS and UEFI, baseboard management",
     {"qualcomm", "MediaTek", "Unisoc", "intel", "AMD", "nvidia", "arm", "Brcmpsirt", "Insyde", "Phoenix", "AMI", "lenovo"}, r"imagination technologies|powervr|lenovo|gigabyte|msi\b|qualcomm|snapdragon|mediatek|unisoc|\bintel\b|\bamd\b|nvidia|\bgpu\b|graphics driver|\bbios\b|uefi|firmware|\bbmc\b|idrac|\bilo\b|supermicro|insyde|phoenix technologies|american megatrends|\bami\b|broadcom|marvell|realtek|trusted firmware|\btpm\b|\bdriver\b"),
    ("Mobile platforms", "Android, iOS and iPadOS, and phone makers' system software",
     {"google_android", "Samsung Mobile", "Xiaomi", "OPPO", "vivo", "Honor", "huawei"}, r"apple multiple products|openharmony|\bandroid\b|\bios\b|ipados|watchos|tvos|visionos|samsung mobile|galaxy|harmonyos|\bmiui\b|hyperos|coloros|funtouch|\bpixel\b|oneplus|oxygenos|emui|magic ?os"),
    ("Operating systems", "Desktop and server operating systems, kernels and core system components",
     {"Linux"}, r"windows|linux kernel|\blinux\b|\bmacos\b|mac os x|os x\b|freebsd|openbsd|netbsd|solaris|\baix\b|z/os|chrome ?os|chromeos|fuchsia|ubuntu|debian|red hat enterprise linux|\brhel\b|suse linux|fedora|centos|\bglibc\b|systemd|\bsudo\b|polkit|grub2?\b|\bkernel\b|opensuse|\bsuse\b|zephyr|freertos|vxworks|\bqnx\b|\brtos\b"),
    ("Enterprise applications and servers", "Business applications, databases, web and application servers, middleware and security products",
     {"oracle", "sap", "ibm", "microsoft", "Atlassian", "splunk", "Elastic", "HCL", "Progress", "hpe", "dell", "cisco", "juniper", "fortinet", "paloalto", "f5", "Citrix", "ivanti", "Sophos", "trendmicro", "Broadcom", "apache", "redhat", "Mattermost", "Salesforce", "SolarWinds", "Zoho", "ManageEngine", "Acronis", "Veeam", "Hitachi", "Lenovo", "HP", "zscaler", "Okta", "Gen", "Absolute", "Axis", "Netskope", "OpenText", "ServiceNow", "Wiz", "Moodle", "TYPO3", "Drupal"},
     r"oracle|peoplesoft|e-business suite|weblogic|\bmysql\b|\bsap\b|netweaver|s/4hana|\bibm\b|websphere|\bdb2\b|qradar|sharepoint|exchange|sql server|dynamics|\biis\b|confluence|\bjira\b|atlassian|servicenow|splunk|elasticsearch|kibana|\belastic\b|\bhcl\b|telerik|sitefinity|\bhpe\b|\bdell\b|apache|tomcat|struts|httpd|nginx|\bspring\b|log4j|jboss|wildfly|postgresql|mongodb|redis|mariadb|salesforce|workday|sitecore|liferay|magento|adobe commerce|experience manager|coldfusion|veeam|commvault|solarwinds|manageengine|zoho|trend micro|symantec|mcafee|trellix|crowdstrike|sentinelone|kaspersky|bitdefender|\beset\b|sophos|drupal|joomla|typo3|moodle|keycloak|okta|fortinet|forticlient|fortisandbox|fortisiem|ivanti|progress software|papercut|craft cms|dotnetnuke|\bdnn\b|kentico|umbraco|nagios|zabbix|checkmk|metabase|\bqlik\b|tableau|grafana|\bwso2\b|tanium|devolutions|kofax|\besri\b|arcgis|dassault|delmia|3dexperience|\bmitel\b|avaya|genesys|trueconf|gladinet|centrestack|triofox|ahsay|smartermail|mdaemon|cpanel|\bwhm\b|plesk|control web panel|\bcwp\b|samsung magicinfo|magicinfo|telemessage|paessler|\bprtg\b|whatsup gold|sysaid|veritas|backup exec|pentaho|hitachi vantara|jasperreports|\btibco\b|vbulletin|redcap|cyberpanel|cobalt strike|fortra|anyconnect|\bcisco\b|citrix|broadcom ca|\bca technologies\b|microsoft"),
    (OSS, "Open-source libraries, tools and applications: those named here, and those reported through GitHub's CNA or a package registry",
     {"GitHub_M", "eclipse", "curl", "openssl", "Python", "isc", "apache", "Go", "rust", "Django"}, r"\bcurl\b|libcurl|openssl|openssh|wolfssl|gnutls|mbed ?tls|libxml2|libxslt|expat|zlib|\bffmpeg\b|imagemagick|graphicsmagick|ghostscript|\bgnu\b|\bsamba\b|\bbind\b|unbound|dnsmasq|\bexim\b|postfix|dovecot|roundcube|\bphp group\b|\bphp\b|ruby on rails|\brails\b|\bruby\b|django|node\.?js|\bpython\b|cpython|\bperl\b|golang|\bopenjdk\b|saltstack|geoserver|osgeo|freerdp|mediawiki|wikimedia|nextcloud|owncloud|phpmyadmin|phpmyfaq|\bmisp\b|openemr|concrete ?cms|getgrav|\bgrav\b|siyuan|frappe|erpnext|jeecg|i-educar|portabilis|zammad|freepbx|sangoma|webmin|\bvim\b|\bemacs\b|\bsqlite|\bxz\b|libssh|rsync|\bcups\b|eclipse|avideo|\bwwbn\b|pi-hole|home assistant|openwrt|matrix-synapse|mastodon|discourse|forgejo|nocodb|appsmith|budibase|strapi|directus|payload cms|\bopencart\b|prestashop|magento open source|\bsuitecrm\b|dolibarr|vtiger|espocrm|glpi|itop|librenms|cacti|icinga|phpbb|mybb|\bsnipe-it\b|\bminio\b|\bpear\b|archive_tar|eyesofnetwork|\bbash\b"),
]
_FAM = [(name, cnas, re.compile(rx)) for name, _, cnas, rx in FAMILIES]
FAMILY_NOTES = {name: note for name, note, _, _ in FAMILIES}
FAMILY_NOTES[EDGE] = "Firewalls, VPNs, gateways and ADCs, routers and network devices, mail and file-transfer appliances and remote-management tools (the five classes of the Edge-device lens)"
FAMILY_ORDER = [EDGE] + [f[0] for f in FAMILIES]
UNCLASSIFIED = "Unclassified"
REGISTRY_RX = re.compile(r"npmjs|pypi|maven|rubygems|packagist|crates\.io|nuget|pkg\.go\.dev|proxy\.golang|hex\.pm|pub\.dev|cocoapods|cran\.r-project|hackage|github\.com/marketplace/actions|swiftpackageindex|open-vsx|marketplace\.visualstudio")
# VulDB reports projects named "<Something> Management System" or "Online <Something> System" from small developers in
# bulk; with VulDB as the CNA such a product is a small web application.
SMALL_WEB_VULDB = re.compile(r"management system|online [\w -]+ system|\bsystem using php\b|in php\b|php project")
# CNAs that assign for one family only take precedence over the patterns (a Patchstack CVE for "Integration for Contact
# Form 7 and Zoho CRM" is a WordPress plugin, whatever its name says).
STRONG_CNA = {"Wordfence": "WordPress plugins and themes", "Patchstack": "WordPress plugins and themes", "WPScan": "WordPress plugins and themes",
              "Chrome": "Browsers", "Linux": "Operating systems", "jenkins": "Developer and CI/CD tools", "GitLab": "Developer and CI/CD tools",
              "google_android": "Mobile platforms"}
# Network devices the Edge-device lens does not name: counted in the Network edge family as routers and network devices,
# while the lens itself (EDGE_RULES, the KEV table's Edge class) stays as it is.
EDGE_FAMILY_EXTRA = re.compile(r"wavlink|edimax|trendnet|\butt\b|arista|brocade|ruijie|\bh3c\b|comfast|\bcudy\b|sapido|belkin|\brouter\b|\bmodem\b|access point|\bgpon\b|\bont\b|\bonu\b|\bcpe\b|\bdsl\b|wireless gateway|mesh wi-?fi|range extender|openwrt|cambium|mimosa|ruckus|extreme networks|allied telesis|peplink|cradlepoint|digi international|teltonika|milesight|sierra wireless|\bgl\.?inet\b")
_VAGUE = {"", "n/a", "unknown", "unspecified", "none", "-", "not applicable", "n/a (n/a)"}


def classify(vendor="", product="", title="", cna="", collection_url="", package_name=""):
    """Return (family, edge_class, basis). edge_class is the Edge-device lens class or ''."""
    v = "" if str(vendor).strip().lower() in _VAGUE else str(vendor)
    p = "" if str(product).strip().lower() in _VAGUE else str(product)
    named = bool(v or p)
    t = f"{v} {p}".lower() if named else str(title or "").lower()[:240]
    basis = "vendor/product" if named else "title"
    ec = edge_class(v, p, title or "") if named else edge_class("", "", t)
    if ec:
        return EDGE, ec, "edge rule"
    if cna in STRONG_CNA:
        return STRONG_CNA[cna], "", "CNA"
    if EDGE_FAMILY_EXTRA.search(t):
        return EDGE, "Router / network device", "vendor/product"
    if cna == "VulDB" and SMALL_WEB_VULDB.search(t):
        return SMALL_WEB, "", "vendor/product"
    for name, _, rx in _FAM:
        if rx.search(t):
            return name, "", basis
    for name, cnas, _ in _FAM:
        if cna in cnas:
            return name, "", "CNA"
    if package_name or (collection_url and REGISTRY_RX.search(str(collection_url).lower())):
        return OSS, "", "registry"
    return UNCLASSIFIED, "", ""


def _self_test():
    cases = [
        (("Fortinet", "FortiOS", "heap overflow in sslvpnd", "fortinet"), (EDGE, "Firewall / VPN")),
        (("Ivanti", "Connect Secure", "", "ivanti"), (EDGE, "Remote-access gateway / ADC")),
        (("SourceCodester", "Online Exam System", "SQL injection", "VulDB"), ("Small web applications", "")),
        (("n/a", "n/a", "Contact Form 7 plugin for WordPress", "Wordfence"), ("WordPress plugins and themes", "")),
        (("Google", "Chrome", "Use after free in V8", "Chrome"), ("Browsers", "")),
        (("Linux", "Linux", "net/sched: fix a race", "Linux"), ("Operating systems", "")),
        (("Microsoft", "Windows 11", "Win32k elevation of privilege", "microsoft"), ("Operating systems", "")),
        (("Microsoft", "Microsoft Exchange Server", "", "microsoft"), (EDGE, "Email / file-transfer appliance")),
        (("Microsoft", "SharePoint Server", "", "microsoft"), ("Enterprise applications and servers", "")),
        (("Qualcomm, Inc.", "Snapdragon", "memory corruption in WLAN", "qualcomm"), ("Chipsets, firmware and drivers", "")),
        (("Siemens", "SIMATIC S7-1500", "", "siemens"), ("Industrial and OT", "")),
        (("VMware", "vCenter Server", "", "vmware"), ("Virtualization, cloud and containers", "")),
        (("Jenkins Project", "Jenkins Script Security Plugin", "", "jenkins"), ("Developer and CI/CD tools", "")),
        (("Adobe", "Acrobat Reader", "", "adobe"), ("Desktop and office applications", "")),
        (("ollama", "ollama", "path traversal", "@huntrdev"), ("AI and machine learning software", "")),
        (("digitalbazaar", "forge", "signature check", "GitHub_M"), ("Open-source projects and packages", "")),
        (("n/a", "n/a", "", "mitre"), (UNCLASSIFIED, "")),
    ]
    bad = []
    for args, want in cases:
        fam, ec, _ = classify(*args)
        if (fam, ec) != want:
            bad.append(f"{args} -> {(fam, ec)}, want {want}")
    reg = classify("acme", "left-pad", "", "VulnCheck", "https://www.npmjs.com", "left-pad")
    if reg[0] != "Open-source projects and packages" or reg[2] != "registry":
        bad.append(f"registry rule: {reg}")
    if edge_class("Zyxel", "USG FLEX", "") != "Firewall / VPN" or edge_class("Cisco", "Secure Email Gateway", "") != "Email / file-transfer appliance":
        bad.append("edge rule order")
    if set(FAMILY_ORDER) - set(FAMILY_NOTES):
        bad.append("every family has a note")
    if bad:
        print("FAIL families\n" + "\n".join(bad))
        sys.exit(1)
    print(f"PASS {len(cases) + 3} checks (product families)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        _self_test()
