// Where a host name stops being a registry's and becomes someone's: "sbi.co.in" is registered under
// "co.in", "evil.net" under "net". A small table of the public suffix list's ICANN part (country
// endings that register one level down), not the whole list, and no private suffixes such as
// github.io: a page on shared hosting is a deeper name here, and may be listed.
//
// A country ending missing from the table is read by its second label: one of the common registry
// words ("co", "com", "org" ...) counts as a suffix, as it almost always is ("abc.com.xx").

/** Country endings and the second labels that are suffixes under them. */
const TABLE = {
  uk: "ac co gov ltd me net nhs org plc police sch",
  in: "ac ai biz co com edu firm gen gov ind info int io me mil net nic org pro res tv",
  au: "asn com edu gov id net org",
  nz: "ac co cri geek gen govt health iwi kiwi maori mil net org parliament school",
  za: "ac agric alt co edu gov law mil net ngo nic nom org school tm web",
  jp: "ac ad co ed go gr lg ne or",
  kr: "ac co es go hs kg mil ms ne or pe re sc",
  br: "adv agr app art blog com coop dev edu eng eti gov ind inf jus leg log med mil mp net org pro rec srv tur tv wiki",
  mx: "com edu gob net org",
  ar: "com edu gob gov int mil net org tur",
  tr: "av bbs bel biz com dr edu gen gov info k12 kep mil name net org pol tel tsk tv web",
  il: "ac co gov idf k12 muni net org",
  ke: "ac co go info me mobi ne or sc",
  ng: "biz com edu gov i mil mobi name net org sch",
  ug: "ac co com go ne or org sc",
  tz: "ac co go hotel info me mil mobi ne or sc tv",
  gh: "com edu gov mil org",
  pk: "biz com edu fam gob gok gon gop gos gov info net org web",
  bd: "ac com edu gov mil net org",
  lk: "ac assn com edu gov grp hotel int ltd net ngo org sch soc web",
  np: "com edu gov mil net org",
  sg: "com edu gov net org per",
  my: "biz com edu gov mil name net org",
  th: "ac co go in mi net or",
  id: "ac biz co desa go mil my net or sch web",
  ph: "com edu gov i mil net ngo org",
  vn: "ac biz com edu gov health info int name net org pro",
  hk: "com edu gov idv net org",
  tw: "club com ebiz edu game gov idv mil net org",
  cn: "ac com edu gov mil net org",
  ru: "ac com edu gov int mil net org pp",
  ua: "com edu gov in net org",
  pl: "biz com edu gov info mil net org priv shop waw",
  eg: "com edu eun gov mil name net org sci",
  sa: "com edu gov med net org pub sch",
  ae: "ac co gov mil net org sch",
  qa: "com edu gov mil name net org sch",
  kw: "com edu emb gov ind net org",
  at: "ac co gv or",
  co: "com edu gov mil net nom org",
  es: "com edu gob nom org",
  fr: "asso com gouv nom prd tm",
  be: "ac",
  pe: "com edu gob mil net nom org",
  ve: "co com edu gob info mil net org web",
  ec: "com edu fin gob gov info med mil net org pro",
  uy: "com edu gub mil net org",
  cl: "co gob gov mil",
  bo: "com edu gob int mil net org tv",
  py: "com coop edu gov mil net org",
  do: "art com edu gob gov mil net org sld web",
  gt: "com edu gob ind mil net org",
  cy: "ac biz com ekloges gov ltd mil net org press pro tm",
  mt: "com edu gov net org",
  zw: "ac co gov mil org",
  bw: "co org",
  kh: "com edu gov mil net org per",
  mm: "com edu gov net org",
  ir: "ac co gov id net org sch",
  iq: "com edu gov mil net org",
  jo: "com edu gov mil name net org sch",
  lb: "com edu gov net org",
  om: "co com edu gov med museum net org pro",
  bh: "com edu gov net org",
  ma: "ac co gov net org press",
  dz: "art asso com edu gov net org pol",
  tn: "com ens fin gov ind info intl nat net org perso tourism",
  et: "biz com edu gov info name net org",
  zm: "ac biz co com edu gov info mil net org sch",
  mz: "ac adv co edu gov mil net org",
  cm: "co com gov net",
  ci: "ac co com ed edu go gouv int net or org",
  sn: "art com edu gouv org perso univ",
  af: "com edu gov net org",
  kz: "com edu gov mil net org",
  uz: "co com net org",
  az: "biz com edu gov info int mil name net org pp pro",
  ge: "com edu gov mil net org pvt",
  am: "co com commune net org",
  by: "com gov mil",
  ba: "com edu gov mil net org",
  rs: "ac co edu gov in org",
  hr: "com from iz name",
  ro: "arts com firm info nom nt org rec store tm www",
  hu: "co info org priv sport tm",
  gr: "com edu gov net org",
  pt: "com edu gov int net nome org publ",
  nf: "com net per rec web arts firm info other store",
  fj: "ac biz com gov info mil name net org pro",
  pg: "com net org",
  sb: "com edu gov net org",
  ws: "com edu gov net org",
  to: "com edu gov mil net org",
  ly: "com edu gov id med net org plc sch",
  mu: "ac co com gov net or org",
  na: "co com org",
  ls: "ac biz co edu gov info net org sc",
  rw: "ac co coop gov mil net org",
  ss: "biz com edu gov me net org sch",
  sd: "com edu gov info med net org tv",
  ao: "co ed gv it og pb",
  mw: "ac biz co com coop edu gov int museum net org",
  gy: "co com edu gov net org",
  tt: "biz co com edu gov info mil name net org pro",
  jm: "com edu gov net org",
  bb: "biz co com edu gov info net org store tv",
  bs: "com edu gov net org",
  bz: "co com edu gov net org",
  ni: "ac biz co com edu gob in info int mil net nom org web",
  cr: "ac co ed fi go or sa",
  pa: "abo ac com edu gob ing med net nom org sld",
  sv: "com edu gob org red",
  hn: "com edu gob mil net org",
  cu: "com edu gov inf net org",
  pr: "biz com edu gov info isla name net org pro",
};

/** Second labels that are almost always a registry's under a two-letter ending the table does not have. */
const COMMON_SECOND = new Set(["ac", "co", "com", "edu", "gob", "gov", "govt", "mil", "ne", "net", "nic", "or", "org", "sch"]);

const SUFFIXES = new Set(Object.entries(TABLE).flatMap(([cc, words]) => words.split(" ").map((w) => `${w}.${cc}`)));

/** Every two-label suffix in the table, as "co.in". */
export const KNOWN_SUFFIXES = Object.freeze([...SUFFIXES].sort());

/**
 * The registry suffix of a host: "co.in" for "a.sbi.co.in", "net" for "a.evil.net". Null for an address
 * (a last label of digits) and for a name that is only a suffix.
 */
export function suffixOf(host) {
  const labels = host.split(".");
  const last = labels[labels.length - 1];
  if (labels.length < 2 || /^\d+$/.test(last)) return null;
  const second = labels[labels.length - 2];
  const two = `${second}.${last}`;
  if (SUFFIXES.has(two)) return two;
  if (last.length === 2 && !(last in TABLE) && COMMON_SECOND.has(second)) return two;
  return last;
}

/** The registered name: "sbi.co.in" for "a.sbi.co.in", or null for an address or a bare suffix. */
export function registrableOf(host) {
  const suffix = suffixOf(host);
  if (suffix === null || host === suffix) return null;
  const rest = host.slice(0, -(suffix.length + 1));
  return `${rest.slice(rest.lastIndexOf(".") + 1)}.${suffix}`;
}

/** The label before the suffix ("sbi" in "a.sbi.co.in"), or null. */
export function nameLabelOf(host) {
  const registrable = registrableOf(host);
  return registrable === null ? null : registrable.slice(0, registrable.indexOf("."));
}
