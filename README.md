# EHR Access Management System (MA-ABE Based)

## 1. Project Title
**Secure EHR Sharing & Access Control using Multi-Authority Attribute-Based Encryption (MA-ABE)**

---

## 2. Overview / Abstract
This project implements a secure **Electronic Health Record (EHR) Access Management System** designed to address the critical challenges of data privacy and fine-grained access control in healthcare environments.

Traditional access control models like Role-Based Access Control (RBAC) are often insufficient for modern healthcare systems where data sharing involves multiple independent organizations (e.g., hospitals, medical boards, insurance providers). This system utilizes **Multi-Authority Attribute-Based Encryption (MA-ABE)** to decentralize trust. Instead of relying on a single central authority, multiple attribute authorities (Medical Authority, Hospital Authority) issue keys to users based on their attributes.

**Key Objectives:**
* **Data Confidentiality:** EHR data is encrypted and stored securely; even the database administrator cannot read it without the correct attributes.
* **Fine-Grained Access Control:** Access policies are embedded directly into the encrypted data (e.g., "Must be a Doctor AND a Cardiologist AND On-Staff").
* **Decentralized Trust:** Users must obtain attribute keys from different authorities to satisfy access policies.

---

## 3. Features
* **User Registration:** Secure onboarding of users with unique Global IDs (GID).
* **Multi-Authority Key Management:** Simulation of multiple independent authorities (Medical Authority & Hospital Authority) issuing cryptographic keys.
* **Attribute-Based Encryption (ABE):** Secure file upload where data is encrypted using a specific access policy string.
* **Hybrid Encryption:** Uses AES-256 for efficient file encryption and MA-ABE for securing the AES keys.
* **Policy Enforcement:** Users can only decrypt and download files if their possessed attributes mathematically satisfy the file's access policy.
* **Metadata Protection:** Encrypted envelopes hide sensitive file metadata (filenames) from the storage layer.
* **Attribute Revocation:** Capability to revoke specific attributes from a user, immediately restricting their access.
* **Audit Logging:** Tamper-evident logging of all system actions (Register, Issue, Upload, Download, Revoke) with SUCCESS/FAILURE status.
* **System Console:** Real-time visual feedback of backend cryptographic operations.

---

## 4. System Architecture
The system follows a modular client-server architecture:

* **Frontend (Client):** A responsive, card-based Web UI built with HTML5, CSS3, and JavaScript. It interacts with the backend via RESTful APIs.
* **Backend (Server):** A Python Flask application that handles API requests, manages user sessions, and orchestrates the cryptographic operations.
* **Cryptographic Engine:** A dedicated core module (`abe_core.py`) implementing the **Rouselakis-Waters 2015 (RW15)** MA-ABE scheme using the `charm-crypto` library.
* **Database & Storage:** * **SQLite Database:** Stores user profiles, serialized attribute keys, encrypted file blobs (ciphertexts), and audit logs.
    * **File Storage:** Simulates secure cloud storage by persisting encrypted blobs.
* **Authorities:**
    * **Medical Authority (MA):** Manages professional attributes (e.g., Doctor, Nurse).
    * **Hospital Authority (HA):** Manages employment attributes (e.g., Staff, Department).

---

## 5. Tech Stack
* **Language:** Python 3.x
* **Backend Framework:** Flask (Microframework)
* **Database:** SQLite (via SQLAlchemy ORM)
* **Cryptography:** * `charm-crypto` (Python bindings for pairing-based cryptography)
    * `PyCryptodome` (AES-256 implementation)
* **Frontend:** HTML, CSS (Custom Responsive Design), JavaScript (Fetch API)
* **Tools:** `pip`, `virtualenv`

---

## 6. Project Workflow
1.  **Register:** A new user (e.g., "Dr. Alice") registers with the system and is assigned a unique Global ID (GID).
2.  **Issue Keys:** The Admin selects an Authority (MA or HA) and issues specific attribute keys (e.g., `MA_DOCTOR`, `HA_STAFF`) to the user. These keys are generated mathematically based on the user's GID.
3.  **Encrypt & Upload:** A Data Owner selects a patient file and defines an access policy (e.g., `(MA_DOCTOR and HA_STAFF)`). The system encrypts the file and stores it.
4.  **Download & Decrypt:** The user attempts to download the file. The system retrieves their keys and attempts to decrypt the file. Success is granted only if the keys match the policy.
5.  **Revoke Key:** The Admin revokes a specific attribute (e.g., removing `HA_STAFF`).
6.  **Verify Access:** The user attempts to download the file again. Access is denied because they no longer satisfy the policy.
7.  **View Logs:** All actions are recorded in the Audit Logs panel for verification.

---

## 7. Installation & Setup Instructions

### Prerequisites
* Python 3.8+
* C Compiler (for building `charm-crypto` dependencies if not pre-built)
* GMP and PBC libraries (required for pairing-based cryptography)

### Steps
1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/yourusername/ma-abe-ehr.git](https://github.com/yourusername/ma-abe-ehr.git)
    cd ma-abe-ehr
    ```

2.  **Create a Virtual Environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: Installing `charm-crypto` may require specific system libraries. Refer to the official documentation if installation fails.)*

4.  **Initialize the Database:**
    The database (`app.db`) is automatically created on the first run. To reset:
    ```bash
    rm app/app.db
    rm -rf crypto_storage/
    ```

5.  **Run the Application:**
    ```bash
    python run.py
    ```

6.  **Access the UI:**
    Open your browser and navigate to: `http://127.0.0.1:5002`

---

## 8. Usage Instructions

### 1. User Management
* Enter a **Username** (e.g., "Dr. Bob") and a **Global ID** (e.g., "bob@hospital.com").
* Click **Register User**.
* *Check the System Console for confirmation.*

### 2. Issue Attribute Keys
* Select the **User GID** you just registered.
* Select an **Authority** (Medical or Hospital).
* Select an **Attribute** (e.g., `CARDIOLOGY`).
* Click **Issue Key**.
* *Repeat this for all attributes the user needs.*

### 3. Upload EHR
* Click **Choose File** to select a medical record.
* Define the **Access Policy** (e.g., `(MA_DOCTOR and MA_CARDIOLOGY)`).
* Click **Encrypt & Upload**.
* *The file is now encrypted and stored.*

### 4. Download EHR
* Enter the **File ID** (visible in logs or returned after upload).
* Enter the **User GID** attempting access.
* Click **Download & Decrypt**.
* *If successful, the file downloads. If failed, an error is shown.*

### 5. Revoke & Audit
* Use the **Revoke Access** panel to remove specific keys.
* Check the **Audit Logs** table to see a history of all operations.

---

## 9. Security Model

### Multi-Authority Attribute-Based Encryption (MA-ABE)
The core security relies on the **Rouselakis-Waters (RW15)** scheme.
* **Decentralization:** No single Key Generation Center (KGC) controls all keys, preventing a single point of compromise.
* **Collision Resistance:** Keys are cryptographically bound to a user's GID. A user cannot combine their keys with another user's keys to gain unauthorized access.
* **Hybrid Encryption:** 1.  A random symmetric key ($K$) is generated.
    2.  Data is encrypted with AES-256 using $K$.
    3.  $K$ is encrypted using MA-ABE under the access policy.
    4.  This ensures efficiency for large files while maintaining flexible access control.

### Policy Logic
Policies support Boolean formulas (AND, OR) over attributes.
* Example: `(MA_DOCTOR and (HA_STAFF or HA_ADMIN))`
* Access is granted $\iff$ User Attributes $\cap$ Policy Attributes satisfies the formula.

---

## 10. System Modules Explained

| Module | Description |
| :--- | :--- |
| **Registration** | Validates unique GIDs and initializes user records. |
| **Key Issuing** | Generates `SecretKey` components for specific attributes using the Authority's `MasterKey`. |
| **Encryption** | Performs AES encryption on file data and encapsulates the key using MA-ABE policies. Handles metadata encryption. |
| **Decryption** | Validates user attributes against the ciphertext policy. If valid, recovers the AES key and decrypts the file. |
| **Revocation** | Logical revocation by removing key components from the database, preventing future decryption operations. |
| **Audit Logging** | Captures timestamped events for security auditing and forensic analysis. |
| **System Console** | Provides transparency by displaying backend status messages to the user. |

---

## 11. Limitations
* **Prototype Implementation:** The system is a proof-of-concept and runs on a local development server.
* **Simulated Authorities:** In a production environment, Authorities would be separate entities/servers. Here, they are simulated within the same application.
* **RAM-Based Parameters:** For demonstration stability, cryptographic parameters are generated fresh on startup (unless persistence is enabled), meaning data might not persist across server restarts in "RAM-Only" mode.

---

## 12. Future Improvements
* **Blockchain Integration:** Store audit logs on a permissioned blockchain (e.g., Hyperledger Fabric) for immutability.
* **IPFS Storage:** Offload encrypted file storage to IPFS (InterPlanetary File System) for decentralized storage.
* **Real-Time Revocation:** Implement epoch-based revocation or key updating mechanisms for stronger security.
* **Multi-Hospital Federation:** Extend the system to support attribute verification across different organizations via APIs.

---

## 13. Screenshots

### Main Dashboard
![Main Dashboard Placeholder](path/to/screenshot_dashboard.png)

### Audit Logs & Revocation
![Audit Logs Placeholder](path/to/screenshot_logs.png)

---

## 14. License
This project is open-source and available under the **MIT License**.

---

## 15. Acknowledgements
* **Charm-Crypto Library** for the underlying ABE implementation.
* **Flask Framework** for the backend infrastructure.
* Research on **Rouselakis-Waters 2015** scheme for MA-ABE.