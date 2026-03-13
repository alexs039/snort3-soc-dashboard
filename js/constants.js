/**
 * Application-wide constants for the SNORT3 SOC Dashboard.
 * These are pure data objects — no side effects, no imports.
 */

/**
 * Alert category definitions.
 * @type {Object.<string, {label:string, color:string, icon:string, mitre:string[]}>}
 */
export const CATS = {
  recon:      { label: "Scan/Recon",  color: "#F59E0B", icon: "🔍", mitre: ["T1046","T1018","T1110"] },
  web_attack: { label: "Web Attack",  color: "#EF4444", icon: "🌐", mitre: ["T1190","T1059","T1083"] },
  dos:        { label: "DoS/DDoS",    color: "#8B5CF6", icon: "⚡", mitre: ["T1498","T1499"] },
  malware:    { label: "Malware/C2",  color: "#DC2626", icon: "🦠", mitre: ["T1071","T1041","T1048"] },
};

/**
 * Severity level definitions (Wazuh rule level → label + color).
 * @type {Object.<string, {label:string, color:string, range:string}>}
 */
export const SEVS = {
  low:      { label: "Faible",   color: "#10B981", range: "1-7"  },
  medium:   { label: "Moyen",    color: "#F59E0B", range: "8-9"  },
  high:     { label: "Élevé",    color: "#EF4444", range: "10-11"},
  critical: { label: "Critique", color: "#DC2626", range: "12+"  },
};

/**
 * Human-readable names for MITRE ATT&CK technique IDs.
 * @type {Object.<string, string>}
 */
export const MITRE_NAMES = {
  T1046: "Network Scan",       T1018: "Remote Discovery", T1110: "Brute Force",
  T1190: "Exploit Public App", T1059: "Command Exec",     T1083: "File Discovery",
  T1498: "Network DoS",        T1499: "Endpoint DoS",     T1071: "App Layer Proto",
  T1041: "Exfil Over C2",      T1048: "Exfil Alt Proto",  T1210: "Exploit Remote Svc",
  T1021: "Remote Services",    T1090: "Proxy/TOR",        T1568: "Dynamic Resolution",
};

/**
 * MITRE ATT&CK tactic groupings with display color and technique lists.
 * @type {Object.<string, {color:string, techniques:string[]}>}
 */
export const MITRE_TACTICS = {
  "Reconnaissance":    { color: "#10B981", techniques: ["T1046","T1018"] },
  "Initial Access":    { color: "#F59E0B", techniques: ["T1190"] },
  "Execution":         { color: "#EF4444", techniques: ["T1059"] },
  "Credential Access": { color: "#DC2626", techniques: ["T1110"] },
  "Lateral Movement":  { color: "#8B5CF6", techniques: ["T1210","T1021"] },
  "Command & Control": { color: "#06B6D4", techniques: ["T1071","T1090"] },
  "Exfiltration":      { color: "#F97316", techniques: ["T1041","T1048"] },
  "Impact":            { color: "#DC2626", techniques: ["T1498","T1499"] },
  "Defense Evasion":   { color: "#3B82F6", techniques: ["T1568"] },
};

/**
 * Mapping from Snort SID to MITRE ATT&CK technique ID.
 * @type {Object.<number, string>}
 */
export const SID_MITRE = {
  9001001:"T1046",9001002:"T1046",9001003:"T1046",9001004:"T1046",9001005:"T1046",
  9001006:"T1046",9001007:"T1018",9001009:"T1046",9001010:"T1110",9002001:"T1083",
  9002002:"T1190",9002003:"T1190",9002004:"T1190",9002005:"T1059",9002006:"T1059",
  9002007:"T1190",9002008:"T1059",9002009:"T1083",9002010:"T1190",9002011:"T1190",
  9002012:"T1190",9002020:"T1498",9002021:"T1498",9002022:"T1498",9002025:"T1210",
  9002027:"T1021",9002028:"T1498",9003001:"T1071",9003002:"T1071",9003003:"T1059",
  9003004:"T1059",9003005:"T1071",9003006:"T1071",9003010:"T1048",9003011:"T1071",
  9003022:"T1041",9003030:"T1210",9003031:"T1110",9003032:"T1071",9003033:"T1059",
  9004001:"T1071",9004002:"T1071",9004003:"T1071",9004004:"T1071",9004005:"T1071",
  9004006:"T1568",9005001:"T1090",9005002:"T1090",9005003:"T1090",9005004:"T1090",
  9005005:"T1090",9005006:"T1090",
};

/**
 * Well-known TCP/UDP port number to service name mapping.
 * @type {Object.<number, string>}
 */
export const PORT_SERVICES = {
  22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP", 110:"POP3", 143:"IMAP",
  443:"HTTPS", 445:"SMB", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL",
  6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB",
};

/**
 * Windows EventID definitions: name, category, severity and icon.
 * @type {Object.<number, {name:string, category:string, severity:string, icon:string}>}
 */
export const WIN_EVENTS = {
  4624: { name:"Login Réussi",        category:"Security", severity:"low",      icon:"✅" },
  4625: { name:"Login Échoué",        category:"Security", severity:"medium",   icon:"❌" },
  4720: { name:"Utilisateur Créé",    category:"Security", severity:"medium",   icon:"👤" },
  4732: { name:"Admin Ajouté",        category:"Security", severity:"high",     icon:"⚠️" },
  4648: { name:"Login Explicite",     category:"Security", severity:"low",      icon:"🔑" },
  11:   { name:"Erreur Kerberos",     category:"System",   severity:"medium",   icon:"🔐" },
  7045: { name:"Service Installé",    category:"System",   severity:"high",     icon:"⚙️" },
  1001: { name:"BSOD",                category:"System",   severity:"critical", icon:"💥" },
};

/**
 * Country lookup by ISO 3166-1 alpha-2 code.
 * Contains capital / representative coordinates for map placement.
 * @type {Object.<string, {name:string, lat:number, lng:number}>}
 */
export const COUNTRIES = {
  JP:{name:"Japon",            lat:35.6762,  lng:139.6503},
  US:{name:"États-Unis",       lat:38.8951,  lng:-77.0364},
  GB:{name:"Royaume-Uni",      lat:51.5074,  lng:-0.1278 },
  DE:{name:"Allemagne",        lat:52.5200,  lng:13.4050 },
  FR:{name:"France",           lat:48.8566,  lng:2.3522  },
  NL:{name:"Pays-Bas",         lat:52.3676,  lng:4.9041  },
  SG:{name:"Singapour",        lat:1.3521,   lng:103.8198},
  AU:{name:"Australie",        lat:-33.8688, lng:151.2093},
  CA:{name:"Canada",           lat:43.6532,  lng:-79.3832},
  BR:{name:"Brésil",           lat:-23.5505, lng:-46.6333},
  KR:{name:"Corée du Sud",     lat:37.5665,  lng:126.9780},
  IN:{name:"Inde",             lat:19.0760,  lng:72.8777 },
  RU:{name:"Russie",           lat:55.7558,  lng:37.6176 },
  CN:{name:"Chine",            lat:39.9042,  lng:116.4074},
  IT:{name:"Italie",           lat:41.9028,  lng:12.4964 },
  ES:{name:"Espagne",          lat:40.4168,  lng:-3.7038 },
  SE:{name:"Suède",            lat:59.3293,  lng:18.0686 },
  CH:{name:"Suisse",           lat:46.9481,  lng:7.4474  },
  PL:{name:"Pologne",          lat:52.2297,  lng:21.0122 },
  UA:{name:"Ukraine",          lat:50.4501,  lng:30.5234 },
  MX:{name:"Mexique",          lat:19.4326,  lng:-99.1332},
  ZA:{name:"Afrique du Sud",   lat:-25.7479, lng:28.2293 },
  NG:{name:"Nigéria",          lat:9.0765,   lng:7.3986  },
  EG:{name:"Égypte",           lat:30.0444,  lng:31.2357 },
  AR:{name:"Argentine",        lat:-34.6037, lng:-58.3816},
  TR:{name:"Turquie",          lat:39.9334,  lng:32.8597 },
  SA:{name:"Arabie Saoudite",  lat:24.7136,  lng:46.6753 },
  AE:{name:"Émirats Arabes",   lat:25.2048,  lng:55.2708 },
  ID:{name:"Indonésie",        lat:-6.2088,  lng:106.8456},
  MY:{name:"Malaisie",         lat:3.1390,   lng:101.6869},
  TH:{name:"Thaïlande",        lat:13.7563,  lng:100.5018},
  VN:{name:"Vietnam",          lat:21.0285,  lng:105.8542},
  PH:{name:"Philippines",      lat:14.5995,  lng:120.9842},
  PK:{name:"Pakistan",         lat:33.6844,  lng:73.0479 },
  BD:{name:"Bangladesh",       lat:23.8103,  lng:90.4125 },
  IR:{name:"Iran",             lat:35.6892,  lng:51.3890 },
  IQ:{name:"Irak",             lat:33.3152,  lng:44.3661 },
  IL:{name:"Israël",           lat:31.7683,  lng:35.2137 },
  PT:{name:"Portugal",         lat:38.7223,  lng:-9.1393 },
  BE:{name:"Belgique",         lat:50.8503,  lng:4.3517  },
  AT:{name:"Autriche",         lat:48.2082,  lng:16.3738 },
  CZ:{name:"Tchéquie",         lat:50.0755,  lng:14.4378 },
  RO:{name:"Roumanie",         lat:44.4268,  lng:26.1025 },
  HU:{name:"Hongrie",          lat:47.4979,  lng:19.0402 },
  GR:{name:"Grèce",            lat:37.9838,  lng:23.7275 },
  FI:{name:"Finlande",         lat:60.1699,  lng:24.9384 },
  NO:{name:"Norvège",          lat:59.9139,  lng:10.7522 },
  DK:{name:"Danemark",         lat:55.6761,  lng:12.5683 },
  NZ:{name:"Nouvelle-Zélande", lat:-36.8485, lng:174.7633},
  HK:{name:"Hong Kong",        lat:22.3193,  lng:114.1694},
  TW:{name:"Taïwan",           lat:25.0330,  lng:121.5654},
  KZ:{name:"Kazakhstan",       lat:51.1694,  lng:71.4491 },
  CL:{name:"Chili",            lat:-33.4489, lng:-70.6693},
  CO:{name:"Colombie",         lat:4.7110,   lng:-74.0721},
  PE:{name:"Pérou",            lat:-12.0464, lng:-77.0428},
  MA:{name:"Maroc",            lat:33.9716,  lng:-6.8498 },
  TN:{name:"Tunisie",          lat:36.8065,  lng:10.1815 },
  KE:{name:"Kenya",            lat:-1.2921,  lng:36.8219 },
  TZ:{name:"Tanzanie",         lat:-6.7924,  lng:39.2083 },
};
