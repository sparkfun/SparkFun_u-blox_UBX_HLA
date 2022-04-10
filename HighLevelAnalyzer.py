# SparkFun u-blox UBX High Level Analyzer

# Based on https://github.com/saleae/hla-text-messages

# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTimeDelta

I2C_ADDRESS_SETTING = 'I2C Address (usually 66 = 0x42)'

class Hla(HighLevelAnalyzer):

    temp_frame = None
    sync_char_1 = 0xB5
    sync_char_2 = 0x62

    # Sync 'state machine'
    looking_for_sync_1      = 0 # Looking for UBX sync char 1 0xB5
    looking_for_sync_2      = 1 # Looking for UBX sync char 2 0x62
    looking_for_class       = 2 # Looking for UBX class byte
    looking_for_ID          = 3 # Looking for UBX ID byte
    looking_for_length_LSB  = 4 # Looking for UBX length bytes
    looking_for_length_MSB  = 5
    processing_payload      = 6 # Processing the payload. Keep going until length bytes have been processed
    looking_for_checksum_A  = 7 # Looking for UBX checksum bytes
    looking_for_checksum_B  = 8
    sync_lost               = 9 # Go into this state if sync is lost (bad checksum etc.)

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
        (0x01, 0x12): "VELNED"
    }

    # Settings:
    i2c_address = NumberSetting(label=I2C_ADDRESS_SETTING, min_value=0, max_value=127)

    # Base output formatting options:
    result_types = {
        'error': {
            'format': 'Error!'
        },
    }

    def __init__(self):
        '''
        Initialize HLA.
        '''

        self.result_types["message"] = {
            'format': '{{{data.str}}}'
        }

    def get_capabilities(self):
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
        self.ubx_state = self.sync_lost # Initialize the state machine

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

    def csum(self, value):
        '''
        Add value to checksums sum1 and sum2
        '''
        self.sum1 = self.sum1 + value
        self.sum2 = self.sum2 + self.sum1
        self.sum1 = self.sum1 & 0xFF
        self.sum2 = self.sum2 & 0xFF

    def analyze_unsigned(self, value, frame, start_byte, end_byte, name, format):
        '''
        Extract an unsigned 8, 16, 32 or 64 bit field
        '''
        if (self.this_is_byte >= start_byte) and (self.this_is_byte <= end_byte):
            if self.this_is_byte == start_byte:
                self.field = value
                self.start_time = frame.start_time
            else:
                self.field += value << ((self.this_is_byte - start_byte) * 8)
            if self.this_is_byte == end_byte:
                if format == 'hex':
                    field_str = hex(str(self.field))
                else:
                    field_str = str(self.field) # Default to 'dec' (decimal)
                return True, AnalyzerFrame('message', self.start_time, frame.end_time, {'str': name + field_str})
            else:
                return True, None
        else:
            return False, None

    def analyze_signed(self, value, frame, start_byte, end_byte, name):
        '''
        Extract a signed 8, 16, 32 or 64 bit field in decimal format
        '''
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

    def analyze_UBX(self, frame, value):
        '''
        Analyze frame according to the UBX interface description

        v0.0.1 : Support UBX-NAV-PVT
        '''

        class_key_list = list(self.UBX_CLASS.keys())
        class_val_list = list(self.UBX_CLASS.values())

        id_key_list = list(self.UBX_ID.keys())
        id_val_list = list(self.UBX_ID.values())

        class_position = class_val_list.index("NAV")
        if (self.msg_class == class_key_list[class_position]): # if self.msg_class == NAV

            id_position = id_val_list.index("PVT")
            if ((self.msg_class,self.ID) == id_key_list[id_position]): # if self.ID == PVT

                success, field = self.analyze_unsigned(value, frame, 0, 3, 'iTOW ', 'dec')
                if success:
                    return field
                success, field = self.analyze_unsigned(value, frame, 4, 5, 'year ', 'dec')
                if success:
                    return field
                if (self.this_is_byte == 6):
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': 'month ' + str(value)})
                elif (self.this_is_byte == 7):
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': 'day ' + str(value)})
                elif (self.this_is_byte == 8):
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': 'hour ' + str(value)})
                elif (self.this_is_byte == 9):
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': 'min ' + str(value)})
                elif (self.this_is_byte == 10):
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': 'sec ' + str(value)})
                elif (self.this_is_byte == 11):
                    return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': 'valid ' + hex(value)})
                success, field = self.analyze_unsigned(value, frame, 12, 15, 'tAcc ', 'dec')
                if success:
                    return field
                success, field = self.analyze_signed(value, frame, 16, 19, 'nano ')
                if success:
                    return field

    def decode(self, frame: AnalyzerFrame):

        maximum_delay = GraphTimeDelta(0.1) # TODO: set maximum_delay according to baud rate / clock speed and message length

        char = "unknown error."

        # setup initial result, if not present
        if self.temp_frame is None:
            self.clear_stored_message(frame)

        # handle serial data and I2C data
        if frame.type == "data" and "data" in frame.data.keys():
            value = frame.data["data"][0]
            char = chr(value)
            #return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': char})

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

        self.append_char(char)
        self.update_end_time(frame)

        # Process data bytes according to ubx_nmea_state
        # For UBX messages:
        # Sync Char 1: 0xB5
        # Sync Char 2: 0x62
        # Class byte
        # ID byte
        # Length: two bytes, little endian
        # Payload: length bytes
        # Checksum: two bytes

        # Check for sync char 1
        if ((self.ubx_state == self.looking_for_sync_1) or (self.ubx_state == self.sync_lost)):
            if (value == self.sync_char_1):
                self.ubx_state = self.looking_for_sync_2
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': char})
            else:
                self.clear_stored_message(frame)
                return None

        # Check for sync char 2
        elif (self.ubx_state == self.looking_for_sync_2):
            if (value == self.sync_char_2):
                self.ubx_state = self.looking_for_class
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': char})
            else:
                self.clear_stored_message(frame)
                return None

        # Check for Class
        elif (self.ubx_state == self.looking_for_class):
            self.ubx_state = self.looking_for_ID
            self.msg_class = value
            self.sum1 = 0 # Clear the checksum
            self.sum2 = 0
            self.csum(value)
            if self.msg_class in self.UBX_CLASS:
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': self.UBX_CLASS[value]})
            else:
                return None

        # Check for ID
        elif (self.ubx_state == self.looking_for_ID):
            self.ubx_state = self.looking_for_length_LSB
            self.ID = value
            self.csum(value)
            if (self.msg_class,self.ID) in self.UBX_ID:
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': self.UBX_ID[self.msg_class,self.ID]})
            else:
                return None

        # Check for Length LSB
        elif (self.ubx_state == self.looking_for_length_LSB):
            self.ubx_state = self.looking_for_length_MSB
            self.length_LSB = value
            self.csum(value)
            self.start_time = frame.start_time
            return None

        # Check for Length MSB
        elif (self.ubx_state == self.looking_for_length_MSB):
            self.ubx_state = self.processing_payload
            self.length_MSB = value
            self.bytes_to_process = self.length_MSB * 256 + self.length_LSB
            self.this_is_byte = 0
            self.csum(value)
            return AnalyzerFrame('message', self.start_time, frame.end_time, {'str': 'Length ' + str(self.bytes_to_process)})

        # Process payload
        elif (self.ubx_state == self.processing_payload):
            if (self.bytes_to_process > 0):
                self.csum(value)
                result = self.analyze_UBX(frame, value)
                self.this_is_byte += 1
                self.bytes_to_process -= 1
                return result
            else:
                self.ubx_state = self.looking_for_checksum_A

        # Checksum A
        if (self.ubx_state == self.looking_for_checksum_A):
            if (value != self.sum1):
                self.ubx_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CK_A"})
            else:
                self.ubx_state = self.looking_for_checksum_B
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CK_A"})

        # Checksum B
        elif (self.ubx_state == self.looking_for_checksum_B):
            if (value != self.sum2):
                self.ubx_state = self.sync_lost
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "INVALID CK_B"})
            else:
                self.ubx_state = self.looking_for_sync_1
                self.clear_stored_message(frame)
                return AnalyzerFrame('message', frame.start_time, frame.end_time, {'str': "Valid CK_B"})

        # This should never happen...
        else:
            self.clear_stored_message(frame)
            return None


