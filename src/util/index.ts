export function getVulnerabilityLink(description): string {
  //returns either "none", a CWE link at mitre.org, or a CVE link at nvd.nist.gov

  let webLink: string = 'none';
  const matches = description.match(/\bhttps?:\/\/(cwe.mitre.org).+html\b/);
  // Example: https://cwe.mitre.org/data/definitions/307.html
  if (matches) {
    webLink = matches[0];
  }
  const matches2 = description.match(
    /\bhttps?:\/\/(cve.mitre.org).*CVE[0-9_-]+\b/,
  );
  // Example: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-2138
  if (matches2) {
    // reformat URL to nvd.nist.gov URL, like https://nvd.nist.gov/vuln/detail/CVE-2021-2138
    const cveNumAry = matches2[0].match(/CVE[0-9_-]+/);
    webLink = `https://nvd.nist.gov/vuln/detail/${cveNumAry[0]}`;
  }
  const matches3 = description.match(
    /\bhttps?:\/\/(nvd.nist.gov).*CVE[0-9_-]+\b/,
  );
  //Example: https://nvd.nist.gov/vuln/detail/CVE-2021-2138
  if (matches3) {
    webLink = matches3[0];
  }
  return webLink;
}

export function getVulnerabilityNumber(link): string {
  const cveMatch = link.match(/CVE[0-9_-]+/);
  //Example: CVE-2021-2138
  if (cveMatch) {
    return cveMatch[0];
  }
  const cweMatch = link.match(/[0-9_-]+\.html/);
  //Example: 307.html
  if (cweMatch) {
    return `CWE-${cweMatch[0].match(/[0-9_-]+/)[0]}`; //trim off the .html
  }
  return 'Unknown vulnerability';
}
