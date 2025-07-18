# SparkFun u-blox UBX High Level Analyzer

# Based on https://github.com/saleae/hla-text-messages

# For more information and documentation about high level analyzers, please go to
# https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTimeDelta

I2C_ADDRESS_SETTING = 'I2C Address (usually 66 = 0x42)'
SPI_CHANNEL_SETTING = 'SPI Channel'
UBLOX_MODULE_SETTING = 'u-blox Module'

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

    # Mini state machine to avoid I2C Bytes-Available being decoded as data
    decode_normal = 0       # Decode bytes as normal
    write_seen_check_FD = 1 # Go into this state when a _write_ to i2c_address is seen
    FD_seen_check_read = 2  # Go into this state if 0xFD is seen immediately after the write
    ignore_avail_LSB = 3    # Ignore this byte - it is the LSB of Bytes-Available
    ignore_avail_MSB = 4    # Ignore this byte - it is the MSB of Bytes-Available

    # UBX Class (Numerical order)
    UBX_CLASS = {
        0x01: "NAV",
        0x02: "RXM",
        0x04: "INF",
        0x05: "ACK",
        0x06: "CFG",
        0x09: "UPD",
        0x0a: "MON",
        0x0b: "AID",
        0x0c: "DBG",
        0x0d: "TIM",
        0x10: "ESF",
        0x13: "MGA",
        0x21: "LOG",
        0x27: "SEC",
        0x28: "HNR",
        0x29: "NAV2",
        0xF0: "NMEA",
        0xF1: "PUBX",
        0xF4: "RTCM2",
        0xF5: "RTCM3",
        0xF6: "SPARTN",
        0xF7: "NMEA-NAV2"
    }

    # UBX ID (Alphabetical order - as per the interface description)
    UBX_ID = {
        # ACK
        (0x05, 0x01): ("ACK", "ACK"),
        (0x05, 0x00): ("ACK", "NACK"),
        # CFG
        (0x06, 0x13): ("CFG", "ANT"),
        (0x06, 0x93): ("CFG", "BATCH"),
        (0x06, 0x09): ("CFG", "CFG"),
        (0x06, 0x06): ("CFG", "DAT"),
        (0x06, 0x70): ("CFG", "DGNSS"),
        (0x06, 0x4c): ("CFG", "ESFA"),
        (0x06, 0x56): ("CFG", "ESFALG"),
        (0x06, 0x4d): ("CFG", "ESFG"),
        (0x06, 0x69): ("CFG", "GEOFENCE"),
        (0x06, 0x3e): ("CFG", "GNSS"),
        (0x06, 0x5c): ("CFG", "HNR"),
        (0x06, 0x02): ("CFG", "INF"),
        (0x06, 0x39): ("CFG", "ITFM"),
        (0x06, 0x47): ("CFG", "LOGFILTER"),
        (0x06, 0x01): ("CFG", "MSG"),
        (0x06, 0x24): ("CFG", "NAV5"),
        (0x06, 0x23): ("CFG", "NAVX5"),
        (0x06, 0x17): ("CFG", "NMEA"),
        (0x06, 0x1e): ("CFG", "ODO"),
        (0x06, 0x3b): ("CFG", "PM2"),
        (0x06, 0x86): ("CFG", "PMS"),
        (0x06, 0x00): ("CFG", "PRT"),
        (0x06, 0x57): ("CFG", "PWR"),
        (0x06, 0x08): ("CFG", "RATE"),
        (0x06, 0x34): ("CFG", "RINV"),  # poll contents of remote inventory
        (0x06, 0x04): ("CFG", "RST"),
        (0x06, 0x16): ("CFG", "SBAS"),
        (0x06, 0x71): ("CFG", "TMODE3"),
        (0x06, 0x31): ("CFG", "TP5"),
        (0x06, 0x1b): ("CFG", "USB"),
        (0x06, 0x8c): ("CFG", "VALDEL"),
        (0x06, 0x8b): ("CFG", "VALGET"),
        (0x06, 0x8a): ("CFG", "VALSET"),
        # ESF
        (0x10, 0x14): ("ESF", "ALG"),
        (0x10, 0x15): ("ESF", "INS"),
        (0x10, 0x02): ("ESF", "MEAS"),
        (0x10, 0x03): ("ESF", "RAW"),
        (0x10, 0x13): ("ESF", "RESETALG"),
        (0x10, 0x10): ("ESF", "STATUS"),
        # HNR
        (0x28, 0x01): ("HNR", "ATT"),
        (0x28, 0x02): ("HNR", "INS"),
        (0x28, 0x00): ("HNR", "PVT"),
        # INF
        (0x04, 0x04): ("INF", "DEBUG"),
        (0x04, 0x00): ("INF", "ERROR"),
        (0x04, 0x02): ("INF", "NOTICE"),
        (0x04, 0x03): ("INF", "TEST"),
        (0x04, 0x01): ("INF", "WARNING"),
        # LOG
        (0x21, 0x07): ("LOG", "CREATE"),
        (0x21, 0x03): ("LOG", "ERASE"),
        (0x21, 0x0e): ("LOG", "FINDTIME"),
        (0x21, 0x08): ("LOG", "INFO"),
        (0x21, 0x09): ("LOG", "RETRIEVE"),
        (0x21, 0x0b): ("LOG", "RETRIEVEPOS"),
        (0x21, 0x0f): ("LOG", "RETRIEVEPOSEXTRA"),
        (0x21, 0x0d): ("LOG", "RETRIEVESTRING"),
        (0x21, 0x04): ("LOG", "STRING"),
        # MGA
        (0x13, 0x60): ("MGA", "ACK"),
        (0x13, 0x20): ("MGA", "ANO"),
        (0x13, 0x03): ("MGA", "BDS"),
        (0x13, 0x80): ("MGA", "DBD"),
        (0x13, 0x21): ("MGA", "FLASH"),
        (0x13, 0x02): ("MGA", "GAL"),
        (0x13, 0x06): ("MGA", "GLO"),
        (0x13, 0x00): ("MGA", "GPS"),
        (0x13, 0x40): ("MGA", "INI"),
        (0x13, 0x05): ("MGA", "QZSS"),
        # MON
        (0x0a, 0x36): ("MON", "COMMS"),
        (0x0a, 0x28): ("MON", "GNSS"),
        (0x0a, 0x09): ("MON", "HW"),
        (0x0a, 0x0b): ("MON", "HW2"),
        (0x0a, 0x37): ("MON", "HW3"),
        (0x0a, 0x02): ("MON", "IO"),
        (0x0a, 0x06): ("MON", "MSGPP"),
        (0x0a, 0x27): ("MON", "PATCH"),
        (0x0a, 0x35): ("MON", "PMP"),
        (0x0a, 0x2b): ("MON", "PT2"),
        (0x0a, 0x38): ("MON", "RF"),
        (0x0a, 0x07): ("MON", "RXBUF"),
        (0x0a, 0x21): ("MON", "RXR"),
        (0x0a, 0x2e): ("MON", "SMGR"),
        (0x0a, 0x31): ("MON", "SPAN"),
        (0x0a, 0x39): ("MON", "SYS"),
        (0x0a, 0x0e): ("MON", "TEMP"),
        (0x0a, 0x08): ("MON", "TXBUF"),
        (0x0a, 0x04): ("MON", "VER"),
        # NAV
        (0x01, 0x05): ("NAV", "ATT"),
        (0x01, 0x60): ("NAV", "AOPSTATUS"),
        (0x01, 0x22): ("NAV", "CLOCK"),
        (0x01, 0x36): ("NAV", "COV"),
        (0x01, 0x31): ("NAV", "DGPS"),
        (0x01, 0x04): ("NAV", "DOP"),
        (0x01, 0x3d): ("NAV", "EELL"),
        (0x01, 0x61): ("NAV", "EOE"),
        (0x01, 0x39): ("NAV", "GEOFENCE"),
        (0x01, 0x37): ("NAV", "HNR"),
        (0x01, 0x13): ("NAV", "HPPOSECEF"),
        (0x01, 0x14): ("NAV", "HPPOSLLH"),
        (0x01, 0x28): ("NAV", "NMI"),
        (0x01, 0x09): ("NAV", "ODO"),
        (0x01, 0x34): ("NAV", "ORB"),
        (0x01, 0x62): ("NAV", "PL"),
        (0x01, 0x01): ("NAV", "POSECEF"),
        (0x01, 0x02): ("NAV", "POSLLH"),
        (0x01, 0x17): ("NAV", "PVAT"),
        (0x01, 0x07): ("NAV", "PVT"),
        (0x01, 0x3C): ("NAV", "RELPOSNED"),
        (0x01, 0x10): ("NAV", "RESETODO"),
        (0x01, 0x35): ("NAV", "SAT"),
        (0x01, 0x32): ("NAV", "SBAS"),
        (0x01, 0x43): ("NAV", "SIG"),
        (0x01, 0x42): ("NAV", "SLAS"),
        (0x01, 0x06): ("NAV", "SOL"),
        (0x01, 0x03): ("NAV", "STATUS"),
        (0x01, 0x3B): ("NAV", "SVIN"),
        (0x01, 0x30): ("NAV", "SVINFO"),
        (0x01, 0x24): ("NAV", "TIMEBDS"),
        (0x01, 0x25): ("NAV", "TIMEGAL"),
        (0x01, 0x23): ("NAV", "TIMEGLO"),
        (0x01, 0x20): ("NAV", "TIMEGPS"),
        (0x01, 0x26): ("NAV", "TIMELS"),
        (0x01, 0x21): ("NAV", "TIMEUTC"),
        (0x01, 0x63): ("NAV", "TIMENAVIC"),
        (0x01, 0x27): ("NAV", "TIMEQZSS"),
        (0x01, 0x64): ("NAV", "TIMETRUSTED"),
        (0x01, 0x11): ("NAV", "VELECEF"),
        (0x01, 0x12): ("NAV", "VELNED"),
        # NAV2
        (0x29, 0x22): ("NAV2", "CLOCK"),
        (0x29, 0x36): ("NAV2", "COV"),
        (0x29, 0x31): ("NAV2", "DGPS"),
        (0x29, 0x04): ("NAV2", "DOP"),
        (0x29, 0x61): ("NAV2", "EOE"),
        (0x29, 0x3d): ("NAV2", "EELL"),
        (0x29, 0x09): ("NAV2", "ODO"),
        (0x29, 0x01): ("NAV2", "POSECEF"),
        (0x29, 0x02): ("NAV2", "POSLLH"),
        (0x29, 0x17): ("NAV2", "PVAT"),
        (0x29, 0x07): ("NAV2", "PVT"),
        (0x29, 0x35): ("NAV2", "SAT"),
        (0x29, 0x32): ("NAV2", "SBAS"),
        (0x29, 0x43): ("NAV2", "SIG"),
        (0x29, 0x42): ("NAV2", "SLAS"),
        (0x29, 0x03): ("NAV2", "STATUS"),
        (0x29, 0x3b): ("NAV2", "SVIN"),
        (0x29, 0x24): ("NAV2", "TIMEBDS"),
        (0x29, 0x25): ("NAV2", "TIMEGAL"),
        (0x29, 0x23): ("NAV2", "TIMEGLO"),
        (0x29, 0x20): ("NAV2", "TIMEGPS"),
        (0x29, 0x26): ("NAV2", "TIMELS"),
        (0x29, 0x63): ("NAV2", "TIMENAVIC"),
        (0x29, 0x21): ("NAV2", "TIMEUTC"),
        (0x29, 0x27): ("NAV2", "TIMEQZSS"),
        (0x29, 0x11): ("NAV2", "VELECEF"),
        (0x29, 0x12): ("NAV2", "VELNED"),
        # RXM
        (0x02, 0x34): ("RXM", "COR"),
        (0x02, 0x84): ("RXM", "MEAS20"),
        (0x02, 0x86): ("RXM", "MEAS50"),
        (0x02, 0x82): ("RXM", "MEASC12"),
        (0x02, 0x80): ("RXM", "MEASD12"),
        (0x02, 0x14): ("RXM", "MEASX"),
        (0x02, 0x72): ("RXM", "PMP"),
        (0x02, 0x41): ("RXM", "PMREQ"),
        (0x02, 0x73): ("RXM", "QZSSL6"),
        (0x02, 0x15): ("RXM", "RAWX"),
        (0x02, 0x59): ("RXM", "RLM"),
        (0x02, 0x32): ("RXM", "RTCM"),
        (0x02, 0x13): ("RXM", "SFRBX"),
        (0x02, 0x33): ("RXM", "SPARTN"),
        (0x02, 0x36): ("RXM", "SPARTNKEY"),
        # SEC
        (0x27, 0x04): ("SEC", "ECSIGN"),
        (0x27, 0x0A): ("SEC", "OSNMA"),
        (0x27, 0x05): ("SEC", "SESSID"),
        (0x27, 0x09): ("SEC", "SIG"),
        (0x27, 0x10): ("SEC", "SIGLOG"),
        (0x27, 0x01): ("SEC", "SIGN"),
        (0x27, 0x03): ("SEC", "UNIQID"),
        # TIM
        (0x0d, 0x11): ("TIM", "DOSC"),
        (0x0d, 0x16): ("TIM", "FCHG"),
        (0x0d, 0x17): ("TIM", "HOC"),
        (0x0d, 0x13): ("TIM", "SMEAS"),
        (0x0d, 0x04): ("TIM", "SVIN"),
        (0x0d, 0x05): ("TIM", "SYNC"),
        (0x0d, 0x03): ("TIM", "TM2"),
        (0x0d, 0x12): ("TIM", "TOS"),
        (0x0d, 0x01): ("TIM", "TP"),
        (0x0d, 0x15): ("TIM", "VCOCAL"),
        (0x0d, 0x06): ("TIM", "VRFY"),
        # UPD
        (0x09, 0x14): ("UPD", "SOS" )
    }

    class_key_list = list(UBX_CLASS.keys())
    class_val_list = list(UBX_CLASS.values())

    id_key_list = list(UBX_ID.keys())
    id_val_list = list(UBX_ID.values())

    # Settings:
    i2c_address = NumberSetting(label=I2C_ADDRESS_SETTING, min_value=1, max_value=127)
    spi_channel = ChoicesSetting(label=SPI_CHANNEL_SETTING, choices=('miso', 'mosi'))
    ublox_module = ChoicesSetting(label=UBLOX_MODULE_SETTING, choices=('M8', 'M6'))

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

        # The decode state machine
        self.decode_state = self.sync_lost

        # For I2C, we need a way to ignore the two Bytes-Available bytes read from register 0xFD
        # to prevent them from being decoded as data
        self.bytes_avail_state = self.decode_normal

        # For I2C, we need a way to ignore any traffic to/from other devices on the bus otherwise
        # it can confuse the decoder. Only analyze data when self.addressMatch is True.
        self.addressMatch = True

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

    # def get_capabilities(self): # Deprecated?
    #     return {
    #         'settings': {
    #             I2C_ADDRESS_SETTING: {
    #                 'type': 'number',
    #                 'minimum': 1,
    #                 'maximum': 127
    #             },
    #             SPI_CHANNEL_SETTING: {
    #                 'type': 'choices',
    #                 'choices': ('miso', 'mosi')
    #             },
    #             UBLOX_MODULE_SETTING: {
    #                 'type': 'choices',
    #                 'choices': ('M8', 'M6')
    #             },
    #         }
    #     }
    
    # def set_settings(self, settings): # Deprecated?
    #     if I2C_ADDRESS_SETTING in settings.keys():
    #         self.i2c_address = settings[I2C_ADDRESS_SETTING]
    #     if SPI_CHANNEL_SETTING in settings.keys():
    #         self.spi_channel = settings[SPI_CHANNEL_SETTING]
    #     if UBLOX_MODULE_SETTING in settings.keys():
    #         self.ublox_module = settings[UBLOX_MODULE_SETTING]

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

    def analyze_array(self, value, frame, start_byte, end_byte, name, fmt):
        """
        Extract an array of hex or decimal values
        """
        if (self.this_is_byte >= start_byte) and (self.this_is_byte <= end_byte):
            if fmt == 'hex':
                field_str = "0x{:02X}".format(value)
            else:
                field_str = str(value)  # Default to 'dec' (decimal)
            return True, AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': name + field_str})
        else:
            return False, None

    def get_ubx_class(self, class_name):
        if class_name in self.class_val_list:
            return self.class_key_list[self.class_val_list.index(class_name)]
        return None
    
    def get_ubx_class_and_id(self, class_name, id_name):
        if (class_name, id_name) in self.id_val_list:
            return self.id_key_list[self.id_val_list.index((class_name, id_name))]
        return (None,None)

    def analyze_ubx(self, frame, value):
        """
        Analyze frame according to the UBX interface description
        """

        if self.msg_class == self.get_ubx_class("ACK"):  # if self.msg_class == ACK

            if ((self.msg_class, self.ID) == self.get_ubx_class_and_id("ACK","ACK")) or (
                    (self.msg_class, self.ID) == self.get_ubx_class_and_id("ACK","NACK")):  # if self.ID == ACK or NACK

                if self.this_is_byte == 0:
                    self.ack_class = value
                    if value in self.UBX_CLASS:
                        class_str = self.UBX_CLASS[value]
                    else:
                        class_str = 'Class'
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': class_str})
                elif self.this_is_byte == 1:
                    if (self.ack_class, value) in self.UBX_ID:
                        id_str = self.UBX_ID[self.ack_class, value][1]
                    else:
                        id_str = 'ID'
                    return AnalyzerFrame('message', frame.start_time, frame.end_time,
                                         {'str': id_str})
                else:
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': '?'})

        elif self.msg_class == self.get_ubx_class("CFG"):  # if self.msg_class == CFG

            if (self.msg_class, self.ID) == self.get_ubx_class_and_id("CFG","PRT"):  # if self.ID == PRT

                # there are both messages with lengths 1 and 20 on M6 _and_ M8, they almost completely match
                if self.length_MSB == 0 and (self.length_LSB == 20 or self.length_LSB == 1):
                    success, field = self.analyze_unsigned(value, frame, 0, 0, 'portID ', 'hex')
                    if success:
                        return field
                if self.length_MSB == 0 and self.length_LSB == 20:
                    # called 'reserved0' on M6 and 'reserved1' on M8
                    name = 'reserved1 '
                    if self.ublox_module == 'M6':
                        name = 'reserved0 '
                    success, field = self.analyze_unsigned(value, frame, 1, 1, name, 'hex')
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
                    name = 'flags '
                    if self.ublox_module == 'M6':
                        name = 'reserved4 '
                    success, field = self.analyze_unsigned(value, frame, 16, 17, name, 'hex')
                    if success:
                        return field
                    # called 'reserved5' on M6 and 'reserved2' on M8
                    name = 'reserved2 '
                    if self.ublox_module == 'M6':
                        name = 'reserved5 '
                    success, field = self.analyze_unsigned(value, frame, 18, 19, name, 'hex')
                    if success:
                        return field


            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("CFG","MSG"):  # if self.ID == MSG

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

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("CFG","RST"):  # if self.ID == RST

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

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("CFG","VALSET"):  # if self.ID == VALSET

                success, field = self.analyze_unsigned(value, frame, 0, 0, 'version ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 1, 1, 'layers ', 'hex')
                if success:
                    return field
                
                success, field = self.analyze_unsigned(value, frame, 4, 7, 'key[0] ', 'hex')
                if success:
                    return field

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("CFG","VALGET"):  # if self.ID == VALGET

                success, field = self.analyze_unsigned(value, frame, 0, 0, 'version ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 1, 1, 'layers ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 4, 7, 'key[0] ', 'hex')
                if success:
                    return field

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("CFG","VALDEL"):  # if self.ID == VALDEL

                success, field = self.analyze_unsigned(value, frame, 0, 0, 'version ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 1, 1, 'layers ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 4, 7, 'key[0] ', 'hex')
                if success:
                    return field


        elif self.msg_class == self.get_ubx_class("MON"):  # if self.msg_class == MON

            if (self.msg_class, self.ID) == self.get_ubx_class_and_id("MON","HW"):  # if self.ID == HW

                # M8: 60 Bytes (VP is 17 bytes). M6: 68 Bytes (VP is 25 bytes).
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
                # M8: lastByte is 59 (VP is 17 bytes). M6: lastByte is 67 (VP is 25 bytes).
                lastByte = self.length_LSB + (self.length_MSB << 8) - 1
                vpNumber = "VP{} ".format(self.this_is_byte - 28)
                success, field = self.analyze_array(value, frame, 28, lastByte - 15, vpNumber, 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, lastByte - 14, lastByte - 14, 'jamInd ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, lastByte - 13, lastByte - 12, 'reserved2 ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, lastByte - 11, lastByte - 8, 'pinIrq ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, lastByte - 7, lastByte - 4, 'pullH ', 'hex')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, lastByte - 3, lastByte, 'pullL ', 'hex')
                if success:
                    return field

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("MON","VER"):  # if self.ID == VER
                # M6 sends swVersion[30], hwVersion[10], romVersion[30], extension[30 * N]
                # M8 sends swVersion[30], hwVersion[10], extension[30 * N]

                if self.this_is_byte <= 39:
                    success, field = self.analyze_string(value, frame, 0, 29, 'swVersion ')
                    if success:
                        return field
                    
                    success, field = self.analyze_string(value, frame, 30, 39, 'hwVersion ')
                    if success:
                        return field
                
                elif self.this_is_byte <= 69 and self.ublox_module == 'M6':
                
                    success, field = self.analyze_string(value, frame, 40, 69, 'romVersion ')
                    if success:
                        return field
                
                else:
                    startByte = self.this_is_byte - 10 # Subtract 10 for the hwVersion
                    startByte //= 30 # Modulo 30
                    startByte *= 30
                    startByte += 10

                    success, field = self.analyze_string(value, frame, startByte, startByte + 29, 'extension ')
                    if success:
                        return field

                
        elif self.msg_class == self.get_ubx_class("NAV"):  # if self.msg_class == NAV

            if (self.msg_class, self.ID) == self.get_ubx_class_and_id("NAV","POSECEF"):  # if self.ID == POSECEF

                success, field = self.analyze_unsigned(value, frame, 0, 3, 'iTOW ', 'dec')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 4, 7, 'ecefX ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 8, 11, 'ecefY ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 12, 15, 'ecefZ ')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 16, 19, 'pAcc ', 'dec')
                if success:
                    return field

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("NAV","POSLLH"):  # if self.ID == POSLLH

                success, field = self.analyze_unsigned(value, frame, 0, 3, 'iTOW ', 'dec')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 4, 7, 'lon ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 8, 11, 'lat ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 12, 15, 'height ')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 16, 19, 'hMSL ')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 20, 23, 'hAcc ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 24, 27, 'vAcc ', 'dec')
                if success:
                    return field

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("NAV","PVT"):  # if self.ID == PVT

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

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("NAV","STATUS"):  # if self.ID == STATUS

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

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("NAV","TIMEGPS"):  # if self.ID == TIMEGPS

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

        elif self.msg_class == self.get_ubx_class("RXM"):  # if self.msg_class == RXM

            if (self.msg_class, self.ID) == self.get_ubx_class_and_id("RXM","PMP"):  # if self.ID == PMP

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

        elif self.msg_class == self.get_ubx_class("INF"):  # if self.msg_class == INF

            if (self.msg_class, self.ID) == self.get_ubx_class_and_id("INF","NOTICE"):  # if self.ID == NOTICE

                success, field = self.analyze_string(value, frame, 0, self.length_LSB + (self.length_MSB << 8) - 1)
                if success:
                    return field

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("INF","ERROR"):  # if self.ID == ERROR

                success, field = self.analyze_string(value, frame, 0, self.length_LSB + (self.length_MSB << 8) - 1)
                if success:
                    return field

            elif (self.msg_class, self.ID) == self.get_ubx_class_and_id("INF","WARNING"):  # if self.ID == WARNING

                success, field = self.analyze_string(value, frame, 0, self.length_LSB + (self.length_MSB << 8) - 1)
                if success:
                    return field

        return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': '.'}) # default to printing a dot for any undecoded bytes

    def decode(self, frame: AnalyzerFrame):

        # maximum_delay = GraphTimeDelta(0.1)
        # TODO: set maximum_delay according to baud rate / clock speed and message length

        # setup initial result, if not present
        if self.temp_frame is None:
            self.clear_stored_message(frame)

        value = None
        char = None

        # handle I2C address frames (read and write)
        if frame.type == "address":
            if frame.data["address"][0] == self.i2c_address: # Is this the address we are looking for?
                self.addressMatch = True

                # Mini state machine to avoid I2C Bytes-Available being decoded as data
                if frame.data["read"] == False: # If this is a Write to our address
                    if self.bytes_avail_state == self.decode_normal:
                        self.bytes_avail_state = self.write_seen_check_FD # Check for 0xFD
                else: # Else if this is a read from our address
                    if self.bytes_avail_state == self.FD_seen_check_read:
                        self.bytes_avail_state = self.ignore_avail_LSB
                    else:
                        self.bytes_avail_state = self.decode_normal
            
            else:
                self.addressMatch = False

            return None

        # exit if we do not have an address match
        if not self.addressMatch:
            return None

        # handle serial data and I2C data
        if frame.type == "data" and "data" in frame.data.keys():
            value = frame.data["data"][0]
            char = chr(value)

            # Check Bytes-Available state machine
            # This only applies to I2C
            # For serial, self.bytes_avail_state will always be self.decode_normal
            if self.bytes_avail_state == self.write_seen_check_FD:
                if value == 0xFD:
                    self.bytes_avail_state = self.FD_seen_check_read
                    return None
                else:
                    self.bytes_avail_state = self.decode_normal
            elif self.bytes_avail_state == self.ignore_avail_LSB:
                self.bytes_avail_state = self.ignore_avail_MSB
                return None
            elif self.bytes_avail_state == self.ignore_avail_MSB:
                self.bytes_avail_state = self.decode_normal
                return None

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
        if frame.type == "result":
            if self.spi_channel == 'miso' and "miso" in frame.data.keys() and frame.data["miso"] != 0:
                value = frame.data["miso"][0]
                char = chr(value)
            elif self.spi_channel == 'mosi' and "mosi" in frame.data.keys() and frame.data["mosi"] != 0:
                value = frame.data["mosi"][0]
                char = chr(value)

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
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "UBX μ"})
            elif value == self.dollar:
                self.decode_state = self.looking_for_asterix
                self.nmea_sum = 0 # Clear the checksum
                self.this_is_byte = 0
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "NMEA $"})
            elif value == self.rtcm_preamble:
                self.decode_state = self.looking_for_RTCM_len1
                self.rtcm_sum = 0 # CRC seed is 0
                self.csum_rtcm(value) # Add preamble to rtcm_sum
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "RTCM 0xD3"})
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
                id_str = self.UBX_ID[self.msg_class, self.ID][1]
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
                # No return. Fall through to self.looking_for_checksum_A.

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
            if self.this_is_byte == 0: # Start of a new NMEA message
                self.field_string = char
                self.start_time = frame.start_time
            else:
                self.field_string += char # Add char to the existing message
            self.this_is_byte += 1 # TODO: use this_is_byte to check for excessive message length (i.e. missing or corrupt asterix)
            if value != self.asterix: # Add value to checksum
                self.csum_nmea(value)
                return None
            else: 
                self.nmea_expected_csum1 = ((self.nmea_sum & 0xf0) >> 4) + 0x30 # Convert MS nibble to ASCII hex
                if (self.nmea_expected_csum1 >= 0x3A): # : follows 9 so add 7 to convert to A-F
                    self.nmea_expected_csum1 += 7
                self.nmea_expected_csum2 = (self.nmea_sum & 0x0f) + 0x30 # Convert LS nibble to ASCII hex
                if (self.nmea_expected_csum2 >= 0x3A): # : follows 9 so add 7 to convert to A-F
                    self.nmea_expected_csum2 += 7
                self.decode_state = self.looking_for_csum1
                return AnalyzerFrame('message', self.start_time, frame.end_time, {'str': self.field_string})

        # NMEA Checksum 1
        elif self.decode_state == self.looking_for_csum1:
            if value != self.nmea_expected_csum1:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM1"})
            else:
                self.decode_state = self.looking_for_csum2
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM1"})

        # NMEA Checksum 2
        elif self.decode_state == self.looking_for_csum2:
            if value != self.nmea_expected_csum2:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM2"})
            else:
                self.decode_state = self.looking_for_term1
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM2"})

        # NMEA Terminator 1 (CR)
        elif self.decode_state == self.looking_for_term1:
            if value != 0x0D:
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CR"})
            else:
                self.decode_state = self.looking_for_term2
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "CR"})

        # NMEA Terminator 2 (LF)
        elif self.decode_state == self.looking_for_term2:
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
            self.length_LSB = value
            self.bytes_to_process = self.length_MSB * 256 + self.length_LSB
            self.this_is_byte = 0
            self.csum_rtcm(value)
            if self.bytes_to_process > 0:
                self.decode_state = self.looking_for_RTCM_type1
            else:
                self.decode_state = self.looking_for_RTCM_csum1
            return AnalyzerFrame('message', self.start_time, frame.end_time,
                                 {'str': 'Length ' + str(self.bytes_to_process)})

        # Check for RTCM Type MSB
        elif self.decode_state == self.looking_for_RTCM_type1:
            self.rtcm_type = value
            self.this_is_byte = self.this_is_byte + 1
            self.csum_rtcm(value)
            self.start_time = frame.start_time
            if self.this_is_byte == self.bytes_to_process:
                self.decode_state = self.looking_for_RTCM_csum1
            else:
                self.decode_state = self.looking_for_RTCM_type2
            return None

        # Check for RTCM Type LSB
        elif self.decode_state == self.looking_for_RTCM_type2:
            self.rtcm_type = (self.rtcm_type << 4) | (value >> 4)
            self.this_is_byte = self.this_is_byte + 1
            self.csum_rtcm(value)
            if self.this_is_byte == self.bytes_to_process:
                self.decode_state = self.looking_for_RTCM_csum1
            else:
                self.decode_state = self.processing_RTCM_payload
            return AnalyzerFrame('message', self.start_time, frame.end_time,
                                 {'str': 'Type ' + str(self.rtcm_type)})

        # Process RTCM payload
        elif self.decode_state == self.processing_RTCM_payload:
            self.this_is_byte = self.this_is_byte + 1
            self.csum_rtcm(value)
            if self.this_is_byte == self.bytes_to_process:
                self.decode_state = self.looking_for_RTCM_csum1
            return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "0x{:02X}".format(value)})

        # RTCM Checksum 1
        elif self.decode_state == self.looking_for_RTCM_csum1:
            if value != ((self.rtcm_sum >> 16) & 0xFF):
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM1"})
            else:
                self.decode_state = self.looking_for_RTCM_csum2
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM1"})

        # RTCM Checksum 2
        elif self.decode_state == self.looking_for_RTCM_csum2:
            if value != ((self.rtcm_sum >> 8) & 0xFF):
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM2"})
            else:
                self.decode_state = self.looking_for_RTCM_csum3
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM2"})

        # RTCM Checksum 3
        elif self.decode_state == self.looking_for_RTCM_csum3:
            if value != (self.rtcm_sum & 0xFF):
                self.decode_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CSUM3"})
            else:
                self.decode_state = self.looking_for_B5_dollar_D3
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CSUM3"})

        # This should never happen...
        self.clear_stored_message(frame)
        return None
