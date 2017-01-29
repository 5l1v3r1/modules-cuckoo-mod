from lib.cuckoo.common.abstracts import Signature

class GlobeRansomware(Signature):
    name = "ransomware_globe"
    description = "Appends known Globe ransomware file extensions to files that have been encrypted"
    severity = 3
    families = []
    categories = ["ransomware"]
    authors = ["Daniel Gallagher"]
    minimum = "1.2"

    def run(self):
        indicators = [
            (".*\.purge$", ["Globe"]),
            (".*\.sdfgklhjsdf$", ["Globe"]),
            (".*\.globe$", ["Globe"]),
            (".*\.blt$", ["Globe"]),
            (".*\.strike$", ["Globe"]),
            (".*\.GSupport$", ["Globe"]),
            (".*\.okean-1955@india\.com\.!dsvgdfvdDVGR3SsdvfEF75sddf#xbkNY45fg6}P{cg\.xtbl$", ["Globe"]),
            (".*\.xitreu@india\.com$", ["Globe"]),
            (".*\.\[mia.kokers@aol\.com\]$", ["Globe"]),
            (".*\.raid10$", ["Globe"]),
            ("[A-Za-z0-9+-]*\.globe$", ["Globe"]),
            (".*\.raid16$", ["Globe"]),
            (".*\.raid15$", ["Globe"]),
            (".*\.GSupport2$", ["Globe"]),
            (".*\.raid20$", ["Globe"]),
            (".*\.cantread$", ["Globe"]),
            (".*\.xitreu$", ["Globe"]),
            (".*\.\support2016@india.com\.xtbl$", ["Globe"]),
            (".*\.help_you@india\.com\.CGzp76HGV832ajfbO\.xtbl$", ["Globe"]),
            (".*\.ghfghfghfgh$", ["Globe"]),
            (".*\.nazarbayev@india\.com$", ["Globe"]),
            (".*\.frozen$", ["Globe"]),
            (".*\.\support2016@india\.com\.dll555$", ["Globe"]),
            (".*\.purged$", ["Globe"]),
            (".*\.globalcrypt$", ["Globe"]),
            (".*\.CGzp76HGV832ajfbO\.xtbl$", ["Globe"]),
            (".*\.bahij2@india.com\.huyred$", ["Globe"]),
            (".*\.decryptallfiles@india\.com$", ["Globe"]),
            (".*\.krya$", ["Globe"]),
            (".*\.svetlanasuvorenko@india\.com$", ["Globe"]),
            (".*\.blackblock$", ["Globe"]),
            (".*\.GSupport3$", ["Globe"]),
            (".*\.siri-down@india\.com$", ["Globe"]),
            (".*\.decryptallfiles3@india\.com$", ["Globe"]),
            (".*\.zendr2$", ["Globe"]),
            (".*\.orgasm@india\.com$", ["Globe"]),
            (".*\.UCRYPT$", ["Globe"]),
            (".*\.zendr4$", ["Globe"]),
            (".*\.zendr3$", ["Globe"]),
            (".*\.ACRYPT$", ["Globe"]),
            (".*\.brute3389@india\.com$", ["Globe"]),
            (".*\.zendrz$", ["Globe"]),
            (".*\.MCrypt$", ["Globe"]),
            (".*\.duhust$", ["Globe"]),
            (".*\.exploit$", ["Globe"]),
            (".*\.MK$", ["Globe"]),
            (".*\.x3m$", ["Globe"]),
            (".*\.grapn206@india\.com$", ["Globe"]),
            (".*\.SGood$", ["Globe"]),
            (".*\.zendrf$", ["Globe"]),
            (".*\.orgasm$", ["Globe"]),
            (".*\.dcrptme$", ["Globe"]),
            (".*\.gurdian-decrypt@india\.com\.ps4$", ["Globe"]),
            (".*\.usdubzub@aol\.com\.ac&^#28hsHK{Peq8138srhbW^\.xtbl$", ["Globe"]),
            (".*\.usdubzub@aol\.com\. vrjhget324bNDJWE^&#bcnd23bdY&$#CEM!\.xtbl$", ["Globe"]),
            (".*\.nazarbayev$", ["Globe"]),
            (".*\.lovewindows$", ["Globe"]),
            (".*\.trust$", ["Globe"]),
            ("[A-Za-z0-9+-]*\.cerber$", ["Globe"]),
            ("[A-Za-z0-9+-]*\.cerbers$", ["Globe"]),
            (".*\.helpdecrypt@india\.com$", ["Globe"]),
            (".*\.unlockvt@india\.com$", ["Globe"]),
            (".*\.FROZEN$", ["Globe"]),
            (".*\.rescuers@india\.com\.3392cYAn548QZeUf\.lock$", ["Globe"]),
            (".*\.sorry$", ["Globe"]),
            (".*\.ziptox1$", ["Globe"]),
            (".*\.\support2016@india\.com\.dll555$", ["Globe"]),
            (".*\.\support2016@india\.com\.xtbl$", ["Globe"]),
            (".*\.usdubzub@aol\.com\. vrjhget324bNDJWE^&#bcnd23bdY&$#CEM!\.xtbl$", ["Globe"]),
            (".*\.helptoyou1@india\.com\.8464DBdhFhbd4\.lock$", ["Globe"]),
            (".*\.decryptallfiles2@india\.com$", ["Globe"]),
            (".*\.your_doctor@india\.com\.Qeg1258rye\.xtbl$", ["Globe"]),
            (".*\.your_doctor@india.com\.8392cYAn548QZeUf\.lock$", ["Globe"]),
            (".*\.RSA2048$", ["Globe"]),
            (".*\.decrypr_helper@india\.com$", ["Globe"]),
            (".*\.gangbang$", ["Globe"]),
            (".*\.crypto-helper@india\.com$", ["Globe"]),
            (".*\.vnature@india\.com$", ["Globe"]),
            (".*\.hnyear$", ["Globe"]),
            (".*\.decryptional$", ["Globe"]),
            (".*\.dehelpers$", ["Globe"]),
        ]

        for indicator in indicators:
            results = self.check_write_file(pattern=indicator[0], regex=True, all=True)
            if results and len(results) > 15:
                if indicator[1]:
                    self.families = indicator[1]
                    self.description = (
                        "Appends a known %s ransomware file extension to "
                        "files that have been encrypted" %
                        "/".join(indicator[1])
                    )
                return True

        return False
