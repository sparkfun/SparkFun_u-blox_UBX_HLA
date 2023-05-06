# SparkFun u-blox UBX High Level Analyzer

# Based on https://github.com/saleae/hla-text-messages

# For more information and documentation about high level analyzers, please go to
# https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTimeDelta

# I2C_ADDRESS_SETTING is not used in v1.0.0. TODO: provide filtering on the selected address only
I2C_ADDRESS_SETTING = 'I2C Address (usually 66 = 0x42)'


class Hla(HighLevelAnalyzer):
    temp_frame = None

    sync_char_1 = 0xB5 # UBX preamble sync 1
    sync_char_2 = 0x62 # UBX preamble sync 2
    dollar = 0x24 # NMEA start delimiter
    asterix = 0x2A # NMEA checksum delimiter
    rtcm_preamble = 0xD3 # RTCM preamble

    # Sync 'state machine'
    looking_for_B5_dollar_D3    = 0 # Looking for UBX 0xB5, NMEA '$' or RTCM 0xD3
    looking_for_sync_2          = 1 # Looking for UBX sync char 2 0x62
    looking_for_class           = 2 # Looking for UBX class byte
    looking_for_ID              = 3 # Looking for UBX ID byte
    looking_for_length_LSB      = 4 # Looking for UBX length bytes
    looking_for_length_MSB      = 5
    processing_UBX_payload      = 6 # Processing the UBX payload. Keep going until length bytes have been processed
    looking_for_checksum_A      = 7 # Looking for UBX checksum bytes
    looking_for_checksum_B      = 8
    sync_lost                   = 9 # Go into this state if sync is lost (bad checksum etc.)
    looking_for_asterix         = 10 # Looking for NMEA '*'
    looking_for_csum1           = 11 # Looking for NMEA checksum bytes
    looking_for_csum2           = 12
    looking_for_term1           = 13 # Looking for NMEA terminating bytes (CR and LF)
    looking_for_term2           = 14
    looking_for_RTCM_len1       = 15 # Looking for RTCM length byte (2 MS bits)
    looking_for_RTCM_len2       = 16 # Looking for RTCM length byte (8 LS bits)
    looking_for_RTCM_type1      = 17 # Looking for RTCM Type byte (8 MS bits, first byte of the payload)
    looking_for_RTCM_type2      = 18 # Looking for RTCM Type byte (4 LS bits, second byte of the payload)
    processing_RTCM_payload     = 19 # Processing RTCM payload bytes
    looking_for_RTCM_csum1      = 20 # Looking for the first 8 bits of the CRC-24Q checksum
    looking_for_RTCM_csum2      = 21 # Looking for the second 8 bits of the CRC-24Q checksum
    looking_for_RTCM_csum3      = 22 # Looking for the third 8 bits of the CRC-24Q checksum

    # UBX Class
    UBX_CLASS = {
        0x05: "ACK",
        0x06: "CFG",
        0x04: "INF",
        0x21: "LOG",
        0x13: "MGA",
        0x0a: "MON",
        0x01: "NAV",
        0x29: "NAV2",
        0x02: "RXM",
        0x27: "SEC",
        0x0d: "TIM",
        0x09: "UPD"
    }

    # UBX ID
    UBX_ID = {
        # ACK
        (0x05, 0x01): "ACK",
        (0x05, 0x00): "NACK",
        # CFG
        (0x06, 0x13): "ANT",
        (0x06, 0x09): "CFG",
        (0x06, 0x06): "DAT",
        (0x06, 0x70): "DGNSS",
        (0x06, 0x69): "GEOFENCE",
        (0x06, 0x3e): "GNSS",
        (0x06, 0x02): "INF",
        (0x06, 0x39): "ITFM",
        (0x06, 0x47): "LOGFILTER",
        (0x06, 0x01): "MSG",
        (0x06, 0x24): "NAV5",
        (0x06, 0x23): "NAVX5",
        (0x06, 0x17): "NMEA",
        (0x06, 0x1e): "ODO",
        (0x06, 0x00): "PRT",
        (0x06, 0x57): "PWR",
        (0x06, 0x08): "RATE",
        (0x06, 0x34): "RINV",  # poll contents of remote inventory
        (0x06, 0x04): "RST",
        (0x06, 0x16): "SBAS",
        (0x06, 0x71): "TMODE3",
        (0x06, 0x31): "TP5",
        (0x06, 0x1b): "USB",
        (0x06, 0x8c): "VALDEL",
        (0x06, 0x8b): "VALGET",
        (0x06, 0x8a): "VALSET",
        # INF
        (0x04, 0x04): "DEBUG",
        (0x04, 0x00): "ERROR",
        (0x04, 0x02): "NOTICE",
        (0x04, 0x03): "TEST",
        (0x04, 0x01): "WARNING",
        # LOG
        (0x21, 0x07): "CREATE",
        (0x21, 0x03): "ERASE",
        (0x21, 0x0e): "FINDTIME",
        (0x21, 0x08): "INFO",
        (0x21, 0x09): "RETRIEVE",
        (0x21, 0x0b): "RETRIEVEPOS",
        (0x21, 0x0f): "RETRIEVEPOSEXTRA",
        (0x21, 0x0d): "RETRIEVESTRING",
        (0x21, 0x04): "STRING",
        # MGA
        (0x13, 0x60): "ACK",
        (0x13, 0x03): "BDS",
        (0x13, 0x80): "DBD",
        (0x13, 0x02): "GAL",
        (0x13, 0x06): "GLO",
        (0x13, 0x00): "GPS",
        (0x13, 0x40): "INI",
        (0x13, 0x05): "QZSS",
        # MON
        (0x0a, 0x36): "COMMS",
        (0x0a, 0x28): "GNSS",
        (0x0a, 0x09): "HW",
        (0x0a, 0x0b): "HW2",
        (0x0a, 0x37): "HW3",
        (0x0a, 0x02): "IO",
        (0x0a, 0x06): "MSGPP",
        (0x0a, 0x27): "PATCH",
        (0x0a, 0x38): "RF",
        (0x0a, 0x07): "RXBUF",
        (0x0a, 0x21): "RXR",
        (0x0a, 0x31): "SPAN",
        (0x0a, 0x39): "SYS",
        (0x0a, 0x08): "TXBUF",
        (0x0a, 0x04): "VER",
        # NAV
        (0x01, 0x22): "CLOCK",
        (0x01, 0x36): "COV",
        (0x01, 0x04): "DOP",
        (0x01, 0x61): "EOE",
        (0x01, 0x39): "GEOFENCE",
        (0x01, 0x13): "HPPOSECEF",
        (0x01, 0x14): "HPPOSLLH",
        (0x01, 0x09): "ODO",
        (0x01, 0x34): "ORB",
        (0x01, 0x62): "PL",
        (0x01, 0x01): "POSECEF",
        (0x01, 0x02): "POSLLH",
        (0x01, 0x07): "PVT",
        (0x01, 0x3C): "RELPOSNED",
        (0x01, 0x10): "RESETODO",
        (0x01, 0x35): "SAT",
        (0x01, 0x32): "SBAS",
        (0x01, 0x43): "SIG",
        (0x01, 0x42): "SLAS",
        (0x01, 0x03): "STATUS",
        (0x01, 0x3B): "SVIN",
        (0x01, 0x24): "TIMEBDS",
        (0x01, 0x25): "TIMEGAL",
        (0x01, 0x23): "TIMEGLO",
        (0x01, 0x20): "TIMEGPS",
        (0x01, 0x26): "TIMELS",
        (0x01, 0x27): "TIMEQZSS",
        (0x01, 0x21): "TIMEUTC",
        (0x01, 0x11): "VELECEF",
        (0x01, 0x12): "VELNED",
        # NAV2
        (0x29, 0x22): "CLOCK",
        (0x29, 0x36): "COV",
        (0x29, 0x04): "DOP",
        (0x29, 0x61): "EOE",
        (0x29, 0x09): "ODO",
        (0x29, 0x01): "POSECEF",
        (0x29, 0x02): "POSLLH",
        (0x29, 0x07): "PVT",
        (0x29, 0x35): "SAT",
        (0x29, 0x32): "SBAS",
        (0x29, 0x43): "SIG",
        (0x29, 0x42): "SLAS",
        (0x29, 0x03): "STATUS",
        (0x29, 0x3b): "SVIN",
        (0x29, 0x24): "TIMEBDS",
        (0x29, 0x25): "TIMEGAL",
        (0x29, 0x23): "TIMEGLO",
        (0x29, 0x20): "TIMEGPS",
        (0x29, 0x26): "TIMELS",
        (0x29, 0x27): "TIMEQZSS",
        (0x29, 0x21): "TIMEUTC",
        (0x29, 0x11): "VELECEF",
        (0x29, 0x12): "VELNED",
        # RXM
        (0x02, 0x34): "COR",
        (0x02, 0x14): "MEASX",
        (0x02, 0x72): "PMP",
        (0x02, 0x41): "PMREQ",
        (0x02, 0x73): "QZSSL6",
        (0x02, 0x15): "RAWX",
        (0x02, 0x59): "RLM",
        (0x02, 0x32): "RTCM",
        (0x02, 0x13): "SFRBX",
        (0x02, 0x33): "SPARTN",
        (0x02, 0x36): "SPARTNKEY",
        # SEC
        (0x27, 0x03): "UNIQID",
        # TIM
        (0x0d, 0x03): "TM2",
        (0x0d, 0x01): "TP",
        (0x0d, 0x06): "VRFY",
        # UPD
        (0x09, 0x14): "SOS"
    }

    class_key_list = list(UBX_CLASS.keys())
    class_val_list = list(UBX_CLASS.values())

    id_key_list = list(UBX_ID.keys())
    id_val_list = list(UBX_ID.values())

    # Settings:
    i2c_address = NumberSetting(label=I2C_ADDRESS_SETTING, min_value=0, max_value=127)

    # Base output formatting options:
    result_types = {
        'error': {
            'format': 'Error!'
        },
    }

    def __init__(self):
        """
        Initialize HLA.
        """

        self.ID = None

        self.decode_state = None

        self.this_is_byte = None
        self.bytes_to_process = None
        self.length_MSB = None
        self.length_LSB = None
        self.msg_class = None
        self.pmp_numBytesUserData = None
        self.pmp_version = None
        self.ack_class = None
        self.field = None
        self.start_time = None
        self.field_string = None
        self.sum1 = 0  # Clear the checksum
        self.sum2 = 0

        self.nmea_sum = 0

        self.rtcm_type = 0
        self.rtcm_sum = 0

        self.result_types["message"] = {
            'format': '{{{data.str}}}'
        }

    @staticmethod
    def get_capabilities():
        return {
            'settings': {
                I2C_ADDRESS_SETTING: {
                    'type': 'number'
                },
            }
        }

    def clear_stored_message(self, frame):
        self.temp_frame = AnalyzerFrame('message', frame.start_time, frame.end_time, {
            'str': ''
        })
        self.decode_state = self.sync_lost  # Initialize the state machine

    def append_char(self, char):
        self.temp_frame.data["str"] += char

    def have_existing_message(self):
        if self.temp_frame is None:
            return False
        if len(self.temp_frame.data["str"]) == 0:
            return False
        return True

    def update_end_time(self, frame):
        self.temp_frame.end_time = frame.end_time

    def csum_ubx(self, value):
        """
        Add value to checksums sum1 and sum2
        """
        self.sum1 = self.sum1 + value
        self.sum2 = self.sum2 + self.sum1
        self.sum1 = self.sum1 & 0xFF
        self.sum2 = self.sum2 & 0xFF

    def csum_nmea(self, value):
        """
        Ex-Or value into checksum
        """
        self.nmea_sum = self.nmea_sum ^ value

    def csum_rtcm(self, value):
        """
        Add value to RTCM checksum using CRC-24Q
        """
        crc = self.rtcm_sum # Seed is 0

        crc ^= value << 16 # XOR-in incoming

        for i in range(8):
            crc <<= 1
            if (crc & 0x1000000):
                # CRC-24Q Polynomial:
                # gi = 1 for i = 0, 1, 3, 4, 5, 6, 7, 10, 11, 14, 17, 18, 23, 24
                # 0b 1 1000 0110 0100 1100 1111 1011
                crc ^= 0x1864CFB # CRC-24Q

        self.rtcm_sum = crc & 0xFFFFFF

    def analyze_string(self, value, frame, start_byte, end_byte, prefix=None):
        """
        Extract a string
        """
        if (self.this_is_byte >= start_byte) and (self.this_is_byte <= end_byte):
            if self.this_is_byte == start_byte:
                self.field_string = chr(value)
                self.start_time = frame.start_time
                return True, None
            elif self.this_is_byte == end_byte:
                self.field_string += chr(value)
                if prefix is not None:
                    self.field_string = prefix + self.field_string
                return True, AnalyzerFrame('message', self.start_time, frame.end_time, {'str': self.field_string})
            else:
                self.field_string += chr(value)
                return True, None
        else:
            return False, None

    def analyze_unsigned(self, value, frame, start_byte, end_byte, name, fmt):
        """
        Extract an unsigned 8, 16, 32 or 64 bit field
        """
        if (self.this_is_byte >= start_byte) and (self.this_is_byte <= end_byte):
            if self.this_is_byte == start_byte:
                self.field = value
                self.start_time = frame.start_time
            else:
                self.field += value << ((self.this_is_byte - start_byte) * 8)
            if self.this_is_byte == end_byte:
                if fmt == 'hex':
                    field_str = hex(self.field)
                else:
                    field_str = str(self.field)  # Default to 'dec' (decimal)
                return True, AnalyzerFrame('message', self.start_time, frame.end_time, {'str': name + field_str})
            else:
                return True, None
        else:
            return False, None

    def analyze_signed(self, value, frame, start_byte, end_byte, name):
        """
        Extract a signed 8, 16, 32 or 64 bit field in decimal format
        """
        if (self.this_is_byte >= start_byte) and (self.this_is_byte <= end_byte):
            if self.this_is_byte == start_byte:
                self.field = value
                self.start_time = frame.start_time
            else:
                self.field += value << ((self.this_is_byte - start_byte) * 8)
            if self.this_is_byte == end_byte:
                twos_comp_neg = 0x80 << ((end_byte - start_byte) * 8)
                twos_comp_pos = 0x7F
                if end_byte > start_byte:
                    for x in range(end_byte - start_byte):
                        twos_comp_pos <<= 8
                        twos_comp_pos |= 0xFF
                self.field = -(self.field & twos_comp_neg) | (self.field & twos_comp_pos)
                field_str = str(self.field)
                return True, AnalyzerFrame('message', self.start_time, frame.end_time, {'str': name + field_str})
            else:
                return True, None
        else:
            return False, None

    def analyze_ubx(self, frame, value):
        """
        Analyze frame according to the UBX interface description

        v1.0.0 : Analyze UBX-ACK-ACK, UBX-ACK-NACK and UBX-NAV-PVT
        v1.0.1 : Add UBX-RXM-PMP and UBX-INF-NOTICE, -ERROR and -WARNING
        v1.0.2 : @maehw Add UBX-CFG-PRT, UBX-CFG-MSG, UBX-CFG-RST, UBX-MON-HW, UBX-MON-VER, UBX-NAV-STATUS, UBX-NAV-TIMEGPS

        Note to self: If/when NAV2 is added, self.id_val_list.index("CLOCK") etc. will find the index for NAV, not NAV2.
        """

        class_position = self.class_val_list.index("ACK")
        if self.msg_class == self.class_key_list[class_position]:  # if self.msg_class == ACK

            id_position_1 = self.id_val_list.index("ACK")
            id_position_2 = self.id_val_list.index("NACK")
            if ((self.msg_class, self.ID) == self.id_key_list[id_position_1]) or (
                    (self.msg_class, self.ID) == self.id_key_list[id_position_2]):  # if self.ID == ACK or NACK

                if self.this_is_byte == 0:
                    self.ack_class = value
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': self.UBX_CLASS[value]})
                elif self.this_is_byte == 1:
                    return AnalyzerFrame('message', frame.start_time, frame.end_time,
                                         {'str': self.UBX_ID[self.ack_class, value]})
                else:
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': '?'})

        class_position = self.class_val_list.index("CFG")
        if self.msg_class == self.class_key_list[class_position]:  # if self.msg_class == CFG

            id_position = self.id_val_list.index("PRT")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == PRT

                # there are both messages with lengths 1 and 20 on M6 _and_ M8, they almost completely match
                if self.length_MSB == 0 and (self.length_LSB == 20 or self.length_LSB == 1):
                    success, field = self.analyze_unsigned(value, frame, 0, 0, 'portID ', 'hex')
                    if success:
                        return field
                if self.length_MSB == 0 and self.length_LSB == 20:
                    # called 'reserved0' on M6 and 'reserved1' on M8
                    success, field = self.analyze_unsigned(value, frame, 1, 1, 'res0M6_res1M8 ', 'hex')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 2, 3, 'txReady ', 'hex')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 4, 7, 'mode ', 'hex')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 8, 11, 'baudrate ', 'dec')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 12, 13, 'inProtoMask ', 'hex')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 14, 15, 'outProtoMask ', 'hex')
                    if success:
                        return field
                    # called 'reserved4' on M6 and 'flags' on M8
                    success, field = self.analyze_unsigned(value, frame, 16, 17, 'res4M6_flagsM8 ', 'hex')
                    if success:
                        return field
                    # called 'reserved5' on M6 and 'reserved2' on M8
                    success, field = self.analyze_unsigned(value, frame, 18, 19, 'res5M6_res2M8 ', 'hex')
                    if success:
                        return field


            id_position = self.id_val_list.index("MSG")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == MSG

                # there are messages with lengths 2, 3 and 8 on M6 _and_ M8, the field sizes and names completely match
                if self.length_MSB == 0 and self.length_LSB in [2, 3, 8]:
                    # datasheet states U1, but hex makes more sense to interpret
                    success, field = self.analyze_unsigned(value, frame, 0, 0, 'msgClass ', 'hex')
                    if success:
                        return field
                    # datasheet states U1, but hex makes more sense to interpret
                    success, field = self.analyze_unsigned(value, frame, 1, 1, 'msgId ', 'hex')
                    if success:
                        return field
                if self.length_MSB == 0 and self.length_LSB in [3, 8]:
                    success, field = self.analyze_unsigned(value, frame, 2, 2, 'rate ', 'dec')
                    if success:
                        return field
                if self.length_MSB == 0 and self.length_LSB == 8:
                    for p in range(3, 7+1):
                        success, field = self.analyze_unsigned(value, frame, p, p, 'rate ', 'dec')
                        if success:
                            return field

            id_position = self.id_val_list.index("RST")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == RST

                # there are messages with length 4 on M6 _and_ M8, the field sizes and names completely match
                if self.length_MSB == 0 and self.length_LSB == 4:
                    success, field = self.analyze_unsigned(value, frame, 0, 1, 'navBbrMask ', 'hex')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 2, 2, 'resetMode ', 'dec')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 3, 3, 'reserved1 ', 'dec')
                    if success:
                        return field


        class_position = self.class_val_list.index("MON")
        if self.msg_class == self.class_key_list[class_position]:  # if self.msg_class == MON

            id_position = self.id_val_list.index("HW")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == HW

                success, field = self.analyze_unsigned(value, frame, 0, 3, 'pinSel ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 4, 7, 'pinBank ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 8, 11, 'pinDir ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 12, 15, 'pinVal ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 16, 17, 'noisePerMS ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 18, 19, 'agcCnt ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 20, 20, 'aStatus ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 21, 21, 'aPower ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 22, 22, 'flags ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 23, 23, 'reserved1 ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 24, 27, 'usedMask ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 28, 52, 'VP ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 53, 53, 'jamInd ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 54, 55, 'reserved2 ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 56, 59, 'pinIrq ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 60, 63, 'pullH ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 64, 67, 'pullL ', 'hex')
                if success:
                    return field

            id_position = self.id_val_list.index("VER")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == VER
                # read the whole version information as one blob; should be NULL-terminated C string, but not seen as such
                assert(self.length_MSB == 0)
                versionLength = self.length_LSB

                success, field = self.analyze_string(value, frame, 0, versionLength-1, f'version info (len={versionLength}): ')
                if success:
                    return field

        class_position = self.class_val_list.index("NAV")
        if self.msg_class == self.class_key_list[class_position]:  # if self.msg_class == NAV

            id_position = self.id_val_list.index("PVT")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == PVT

                success, field = self.analyze_unsigned(value, frame, 0, 3, 'iTOW ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 4, 5, 'year ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 6, 6, 'month ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 7, 7, 'day ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 8, 8, 'hour ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 9, 9, 'min ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 10, 10, 'sec ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 11, 11, 'valid ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 12, 15, 'tAcc ', 'dec')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 16, 19, 'nano ')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 20, 20, 'fixType ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 21, 21, 'flags ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 22, 22, 'flags2 ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 23, 23, 'numSV ', 'dec')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 24, 27, 'lon ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 28, 31, 'lat ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 32, 35, 'height ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 36, 39, 'hMSL ')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 40, 43, 'hAcc ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 44, 47, 'vAcc ', 'dec')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 48, 51, 'velN ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 52, 55, 'velE ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 56, 59, 'velD ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 60, 63, 'gSpeed ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 64, 67, 'headMot ')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 68, 71, 'sAcc ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 72, 75, 'headAcc ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 76, 77, 'pDOP ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 78, 79, 'flags3 ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 80, 83, 'reserved0 ', 'hex')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 84, 87, 'headVeh ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 88, 89, 'magDec ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 90, 91, 'magAcc ')
                if success:
                    return field

            id_position = self.id_val_list.index("STATUS")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == STATUS

                success, field = self.analyze_unsigned(value, frame, 0, 3, 'iTOW ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 4, 4, 'gpsFix ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 5, 5, 'flags ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 6, 6, 'fixStat ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 7, 7, 'flags2 ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 8, 11, 'ttff ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 12, 15, 'msss ', 'dec')
                if success:
                    return field

            id_position = self.id_val_list.index("TIMEGPS")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == TIMEGPS

                success, field = self.analyze_unsigned(value, frame, 0, 3, 'iTOW ', 'dec')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 4, 7, 'fTOW ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 8, 9, 'week ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 10, 10, 'leapS ')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 11, 11, 'valid ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 12, 15, 'tAcc ', 'hex')
                if success:
                    return field

        class_position = self.class_val_list.index("RXM")
        if self.msg_class == self.class_key_list[class_position]:  # if self.msg_class == RXM

            id_position = self.id_val_list.index("PMP")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == PMP

                success, field = self.analyze_unsigned(value, frame, 0, 0, 'version ', 'dec')
                if success:
                    self.pmp_version = value
                    return field
                success, field = self.analyze_unsigned(value, frame, 4, 7, 'timeTag ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 8, 11, 'uniqueWord[0] ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 12, 15, 'uniqueWord[1] ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 16, 17, 'serviceIdentifier ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 18, 18, 'spare ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 19, 19, 'uniqueWordBitErrors ', 'dec')
                if success:
                    return field

                if self.pmp_version == 0x01:
                    success, field = self.analyze_unsigned(value, frame, 1, 1, 'reserved0 ', 'hex')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 2, 3, 'numBytesUserData ', 'dec')
                    if success:
                        if self.this_is_byte == 2:
                            self.pmp_numBytesUserData = value
                        else:
                            self.pmp_numBytesUserData += value << 8
                        return field
                    success, field = self.analyze_unsigned(value, frame, 20, 21, 'fecBits ', 'dec')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 22, 22, 'ebno ', 'dec')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 23, 23, 'reserved1 ', 'hex')
                    if success:
                        return field
                    if self.this_is_byte == 24:
                        self.start_time = frame.start_time
                        return None
                    if self.this_is_byte == 24 + self.pmp_numBytesUserData - 1:
                        return AnalyzerFrame('message', self.start_time, frame.end_time, {'str': 'userData'})
                    return None
                else:  # PMP version == 0
                    success, field = self.analyze_unsigned(value, frame, 1, 3, 'reserved0 ', 'hex')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 524, 525, 'fecBits ', 'dec')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 526, 526, 'ebno ', 'dec')
                    if success:
                        return field
                    success, field = self.analyze_unsigned(value, frame, 527, 527, 'reserved1 ', 'hex')
                    if success:
                        return field
                    if self.this_is_byte == 20:
                        self.start_time = frame.start_time
                        return None
                    if self.this_is_byte == 523:
                        return AnalyzerFrame('message', self.start_time, frame.end_time, {'str': 'userData'})
                    return None

        class_position = self.class_val_list.index("INF")
        if self.msg_class == self.class_key_list[class_position]:  # if self.msg_class == INF

            id_position = self.id_val_list.index("NOTICE")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == NOTICE

                success, field = self.analyze_string(value, frame, 0, self.length_LSB + (self.length_MSB << 8) - 1)
                if success:
                    return field

            id_position = self.id_val_list.index("ERROR")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == ERROR

                success, field = self.analyze_string(value, frame, 0, self.length_LSB + (self.length_MSB << 8) - 1)
                if success:
                    return field

            id_position = self.id_val_list.index("WARNING")
            if (self.msg_class, self.ID) == self.id_key_list[id_position]:  # if self.ID == WARNING

                success, field = self.analyze_string(value, frame, 0, self.length_LSB + (self.length_MSB << 8) - 1)
                if success:
                    return field

        return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': '.'})

    def decode(self, frame: AnalyzerFrame):

        # maximum_delay = GraphTimeDelta(0.1)
        # TODO: set maximum_delay according to baud rate / clock speed and message length

        # setup initial result, if not present
        if self.temp_frame is None:
            self.clear_stored_message(frame)

        value = None
        char = None

        # handle serial data and I2C data
        if frame.type == "data" and "data" in frame.data.keys():
            value = frame.data["data"][0]
            char = chr(value)
            # return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': char}) # Useful for debugging

        # handle I2C address
        # if frame.type == "address":
        #     value = frame.data["address"][0]
        #     # if we have an existing message, send it
        #     if self.have_existing_message() == True:
        #         ret = self.temp_frame
        #         self.clear_stored_message(frame)
        #         self.append_char("address: " + hex(value) + ";")
        #         return ret
        #     # append the address to the beginning of the new message
        #     self.append_char("address: " + hex(value) + ";")
        #     return None

        # handle I2C start condition
        # if frame.type == "start":
        #     return

        # handle I2C stop condition
        # if frame.type == "stop":
        #     if self.have_existing_message() == True:
        #         ret = self.temp_frame
        #         self.temp_frame = None
        #         return ret
        #     self.temp_frame = None
        #     return

        # handle SPI byte
        # if frame.type == "result":
        #     char = ""
        #     if "miso" in frame.data.keys() and frame.data["miso"] != 0:
        #         char += chr(frame.data["miso"])
        #     if "mosi" in frame.data.keys() and frame.data["mosi"] != 0:
        #         char += chr(frame.data["mosi"])

        # Check for a timeout event
        # if self.temp_frame is not None:
        #     if self.temp_frame.end_time + maximum_delay < frame.start_time:
        #         self.clear_stored_message(frame)
        #         return "TIMEOUT"

        if value is None:
            return None

        self.append_char(char)
        self.update_end_time(frame)

        # Process data bytes according to decode_state
        # For UBX messages:
        # Sync Char 1: 0xB5
        # Sync Char 2: 0x62
        # Class byte
        # ID byte
        # Length: two bytes, little endian
        # Payload: length bytes
        # Checksum: two bytes

        # For NMEA messages:
        # Starts with a '$'
        # The next five characters indicate the message type (stored in nmea_char_1 to nmea_char_5)
        # Message fields are comma-separated
        # Followed by an '*'
        # Then a two character checksum (the logical exclusive-OR of all characters between the $ and the * as ASCII hex)
        # Ends with CR LF

        # For RTCM messages:
        # Byte0 is 0xD3
        # Byte1 contains 6 unused bits plus the 2 MS bits of the message length
        # Byte2 contains the remainder of the message length
        # Byte3 contains the first 8 bits of the message type
        # Byte4 contains the last 4 bits of the message type and (optionally) the first 4 bits of the sub type
        # Byte5 contains (optionally) the last 8 bits of the sub type
        # Payload
        # Checksum: three bytes CRC-24Q (calculated from Byte0 to the end of the payload, with seed 0)

        # Check for UBX 0xB5, NMEA $ or RTCM 0xD3
        if (self.decode_state == self.looking_for_B5_dollar_D3) or (self.decode_state == self.sync_lost):
            if value == self.sync_char_1:
                self.decode_state = self.looking_for_sync_2
                self.temp_frame.start_time = frame.start_time
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "UBX"})
            elif value == self.dollar:
                self.decode_state = self.looking_for_asterix
                self.nmea_sum = 0 # Clear the checksum
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "NMEA"})
            elif value == self.rtcm_preamble:
                self.decode_state = self.looking_for_RTCM_len1
                self.rtcm_sum = 0 # CRC seed is 0
                self.csum_rtcm(value) # Add preamble to rtcm_sum
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "RTCM"})
            else:
                self.clear_stored_message(frame)
                return None

        # Check for sync char 2
        elif self.decode_state == self.looking_for_sync_2:
            if value == self.sync_char_2:
                self.decode_state = self.looking_for_class
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': char})
            else:
                self.clear_stored_message(frame)
                return None

        # Check for Class
        elif self.decode_state == self.looking_for_class:
            self.decode_state = self.looking_for_ID
            self.msg_class = value
            self.sum1 = 0  # Clear the checksum
            self.sum2 = 0
            self.csum_ubx(value)
            if self.msg_class in self.UBX_CLASS:
                class_str = self.UBX_CLASS[value]
            else:
                class_str = 'Class'
            return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': class_str})

        # Check for ID
        elif self.decode_state == self.looking_for_ID:
            self.decode_state = self.looking_for_length_LSB
            self.ID = value
            self.csum_ubx(value)
            if (self.msg_class, self.ID) in self.UBX_ID:
                id_str = self.UBX_ID[self.msg_class, self.ID]
            else:
                id_str = 'ID'
            return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': id_str})

        # Check for Length LSB
        elif self.decode_state == self.looking_for_length_LSB:
            self.decode_state = self.looking_for_length_MSB
            self.length_LSB = value
            self.csum_ubx(value)
            self.start_time = frame.start_time
            return None

        # Check for Length MSB
        elif self.decode_state == self.looking_for_length_MSB:
            self.decode_state = self.processing_UBX_payload
            self.length_MSB = value
            self.bytes_to_process = self.length_MSB * 256 + self.length_LSB
            self.this_is_byte = 0
            self.csum_ubx(value)
            return AnalyzerFrame('message', self.start_time, frame.end_time,
                                 {'str': 'Length ' + str(self.bytes_to_process)})

        # Process payload
        elif self.decode_state == self.processing_UBX_payload:
            if self.bytes_to_process > 0:
                self.csum_ubx(value)
                result = self.analyze_ubx(frame, value)
                self.this_is_byte += 1
                self.bytes_to_process -= 1
                return result
            else:
                self.decode_state = self.looking_for_checksum_A

        # Checksum A
        if self.decode_state == self.looking_for_checksum_A:
            if value != self.sum1:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CK_A"})
            else:
                self.decode_state = self.looking_for_checksum_B
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CK_A"})

        # Checksum B
        elif self.decode_state == self.looking_for_checksum_B:
            if value != self.sum2:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CK_B"})
            else:
                self.decode_state = self.looking_for_B5_dollar_D3
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CK_B"})

        # Process NMEA payload
        elif self.decode_state == self.looking_for_asterix:
            if value != self.asterix: # Add value to checksum
                self.csum_nmea(value)
            else: 
                self.nmea_expected_csum1 = ((self.nmea_sum & 0xf0) >> 4) + 0x30 # Convert MS nibble to ASCII hex
                if (self.nmea_expected_csum1 >= 0x3A): # : follows 9 so add 7 to convert to A-F
                    self.nmea_expected_csum1 += 7
                self.nmea_expected_csum2 = (self.nmea_sum & 0x0f) + 0x30 # Convert LS nibble to ASCII hex
                if (self.nmea_expected_csum2 >= 0x3A): # : follows 9 so add 7 to convert to A-F
                    self.nmea_expected_csum2 += 7
                self.decode_state = self.looking_for_csum1
            return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': char})

        # NMEA Checksum 1
        if self.decode_state == self.looking_for_csum1:
            if value != self.nmea_expected_csum1:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM1"})
            else:
                self.decode_state = self.looking_for_csum2
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM1"})

        # NMEA Checksum 2
        if self.decode_state == self.looking_for_csum2:
            if value != self.nmea_expected_csum2:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM2"})
            else:
                self.decode_state = self.looking_for_term1
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM2"})

        # NMEA Terminator 1 (CR)
        if self.decode_state == self.looking_for_term1:
            if value != 0x0D:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CR"})
            else:
                self.decode_state = self.looking_for_term2
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "CR"})

        # NMEA Terminator 2 (LF)
        if self.decode_state == self.looking_for_term2:
            if value != 0x0A:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID LF"})
            else:
                self.decode_state = self.looking_for_B5_dollar_D3
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "LF"})

        # Check for RTCM Length MSB
        elif self.decode_state == self.looking_for_RTCM_len1:
            self.decode_state = self.looking_for_RTCM_len2
            self.length_MSB = value
            self.csum_rtcm(value)
            self.start_time = frame.start_time
            return None

        # Check for RTCM Length LSB
        elif self.decode_state == self.looking_for_RTCM_len2:
            self.decode_state = self.looking_for_RTCM_type1
            self.length_LSB = value
            self.bytes_to_process = self.length_MSB * 256 + self.length_LSB
            self.this_is_byte = 0
            self.csum_rtcm(value)
            return AnalyzerFrame('message', self.start_time, frame.end_time,
                                 {'str': 'Length ' + str(self.bytes_to_process)})

        # Check for RTCM Type MSB
        elif self.decode_state == self.looking_for_RTCM_type1:
            self.decode_state = self.looking_for_RTCM_type2
            self.rtcm_type = value
            self.this_is_byte = self.this_is_byte + 1
            self.csum_rtcm(value)
            self.start_time = frame.start_time
            return None

        # Check for RTCM Type MSB
        elif self.decode_state == self.looking_for_RTCM_type2:
            self.decode_state = self.processing_RTCM_payload
            self.rtcm_type = (self.rtcm_type << 4) | (value >> 4)
            self.this_is_byte = self.this_is_byte + 1
            self.csum_rtcm(value)
            return AnalyzerFrame('message', self.start_time, frame.end_time,
                                 {'str': 'Type ' + str(self.rtcm_type)})

        # Process RTCM payload
        elif self.decode_state == self.processing_RTCM_payload:
            self.this_is_byte = self.this_is_byte + 1
            self.csum_rtcm(value)
            if self.this_is_byte == self.bytes_to_process:
                self.decode_state = self.looking_for_RTCM_csum1
            return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "0x{:02x}".format(value)})

        # RTCM Checksum 1
        if self.decode_state == self.looking_for_RTCM_csum1:
            if value != ((self.rtcm_sum >> 16) & 0xFF):
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM1"})
            else:
                self.decode_state = self.looking_for_RTCM_csum2
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM1"})

        # RTCM Checksum 2
        if self.decode_state == self.looking_for_RTCM_csum2:
            if value != ((self.rtcm_sum >> 8) & 0xFF):
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM2"})
            else:
                self.decode_state = self.looking_for_RTCM_csum3
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM2"})

        # RTCM Checksum 3
        if self.decode_state == self.looking_for_RTCM_csum3:
            if value != (self.rtcm_sum & 0xFF):
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM3"})
            else:
                self.decode_state = self.looking_for_B5_dollar_D3
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM3"})

        # This should never happen...
        else:
            self.clear_stored_message(frame)
            return None
