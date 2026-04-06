## Section 0: Definitions
**Contractor:** For the purposes of this license, a "Contractor" is defined as any private individual, corporation, or non-governmental organization (NGO) 
performing work, providing services, or developing software under a formal agreement, purchase order, or task mandate from a government agency. This includes both prime contractors and subcontractors.

**Governmental Usage:** For the purposes of this license, "Governmental Usage" is defined as any use, deployment, integration, 
or modification of the software performed by, for, or on behalf of a government entity. This includes, but is not limited to:
* Work performed by government employees.
* Work performed by **Contractors** (as defined above) to fulfill a government contract, mission, or mandate.
* Any instance where the software is hosted on government-controlled infrastructure or used to process government-owned or government-classified data.

---

## Section 1: Third-Party Components

**OpenPGP.js:** This project utilizes OpenPGP.js in two forms. The server-side Node.js backend uses the openpgp npm package (v6.x), licensed under LGPL-3.0-or-later. The client-side public interface uses a vendored openpgp.min.js (v5.11.0), also licensed under LGPL-3.0-or-later. Consistent with LGPL requirements, both are used as external dependencies and the full source is published. For more information, visit https://openpgpjs.org/.

**Tor Project:** The Onion-Gateway component utilizes the Tor software. Tor is licensed under the Revised BSD License (3-clause).

**Alpine Linux:** The gateway base image utilizes Alpine Linux, which incorporates components under the GPL and other open-source licenses.

**su-exec:** A minimal privilege-drop utility included in the Tor container, licensed under the MIT License.

**Nginx:** The web proxy component utilizes Nginx, licensed under the 2-clause BSD-like license.
**OTHER THIRD-PARTY DEPENDENCIES:** 

**bcryptjs:** (MIT)

**cookie-parser:** (MIT)

**express: (MIT)**

**express-rate-limit:** (MIT)

**helmet:** (MIT)

**jsonwebtoken:** (MIT)

**morgan:** (MIT)

**multer:** (MIT)

**WARRANTY DISCLAIMER FOR THIRD-PARTY COMPONENTS:** All third-party components listed above are provided by their respective
copyright holders "AS IS" without warranty of any kind. This project’s inclusion of these components does not extend the creator's
liability to these third-party works.

---

## Section 2: Non-Governmental Usage
**FOR NON-GOVERNMENT AFFILIATED USAGE:**

Copyright (c) 2026 OpLumina

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”) for **non-governmental** usage, 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**OUTSIDE OF THE MODIFIED PROVISIONS OF THIS LICENSE FOR GOVERNMENTAL USAGE, THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

---

## Section 3: United States and Foreign Government Usage

**UNITED STATES GOVERNMENT USE PROVISION:** Any United States federal, state, or local government agency, department, or affiliated entity 
(including **Contractors** for the United States Government, provided the software is used for Governmental Usage as defined in Section 0.) 
is permitted to use, modify, and distribute this software under the terms of this license, provided that they notify the creator 
via email at **cm.stupak@gmail.com** within 30 days of deployment, integration, or modification with the following regulations:

1. Notification is only required once per Organization.
2. Reason for usage is not required.
3. The notifying entity must provide the name of the primary parent organization; see bullet points below for details:
    * **Federal Level:** Must specify the Cabinet-level Department or Independent Agency (e.g., United States Department of Energy, not "USG" or "Grid Office" or "Executive Branch").
    * **State Level:** Must specify the State and the specific Department or Agency (e.g., California Department of Justice).
    * **Local Level:** Must specify the Municipality/County and the specific Office (e.g., Cook County Sheriff's Office or City of Seattle IT Department).

**NON-UNITED STATES, FOREIGN GOVERNMENT USE PROVISION:** Any foreign (non-US) government agency, department, or state-affiliated entity (including **Contractors** for a foreign government) is permitted to use, 
modify, and distribute this software ONLY upon notification to the creator via email at **cm.stupak@gmail.com**. Use is subject to the following regulations:

1. Notification is only required once per Organization.
2. The organization name and country of origin must be clearly stated; **generic identifiers (e.g., "Canadian Government") are insufficient** and the specific Ministry, Department, or Agency must be identified.
3. Usage must comply with all applicable US export control laws and sanctions.

The above copyright notice, this permission notice, and the government use provision shall be included in all copies or substantial portions of the Software.

**OUTSIDE OF THE MODIFIED PROVISIONS OF THIS LICENSE FOR GOVERNMENTAL USAGE, THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**


## Section 4: Infrastructure & Provenance

**4.1 Hardened Base Images:**
The Node.js backend and Nginx proxy are built upon STIG-hardened, FIPS-validated images sourced from the **DoD Iron Bank (Platform One)**.
* **Backend:** `registry1.dso.mil/ironbank/opensource/nodejs/nodejs22`
* **Shield:** `registry1.dso.mil/ironbank/opensource/nginx/nginx:1.29.4`
Liability for vulnerabilities within these base operating systems or language runtimes remains with the respective upstream maintainers and the Iron Bank hardening process.

**4.2 Network-Isolated Gateway Build:**
The Tor Gateway utilizes a "Network-Isolated Build" process (as detailed in `tor.Dockerfile`). All binaries are pre-fetched and verified before container construction. 
The creator of this software is not responsible for the integrity of third-party binaries if they are sourced from unverified or compromised mirrors.

**4.3 Security & Key Management:**
Consistent with the **"AS IS"** provisions in Sections 2 and 3, the user acknowledges sole responsibility for:
* **PGP Management:** The generation, offline backup, and protection of the PGP private key and its associated passphrase.
* **Tor Identity:** The permanence and security of the `.onion` hostname and secret keys generated by the Tor service.
* **Resource Limits:** Maintenance of the STIG-compliant resource constraints (CPU/Memory/PIDS) defined in the orchestration metadata.




## Section 5: Governing Law
This license shall be governed by and construed in accordance with United States Federal Law and the State of Washington in the United States, without regard to conflict of law principles.


## Section 6: Licensing Questions
**ANY QUESTIONS ABOUT LICENSING CAN BE DIRECTED TO cm.stupak@gmail.com

Original Repository: https://github.com/OpLumina/Secure-Intelligence-Transmission-Portal**
