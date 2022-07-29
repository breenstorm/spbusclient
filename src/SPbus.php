<?php

/**********************************************************************

PHP SPBus API for Schleifenbauer PDUs

Schleifenbauer Engineering B.V.
All rights reserved, no warranties
Last update: 2013-11-21, by B. Vaessen

 ***********************************************************************/

namespace Breenstorm\SPbusClient;

// Require RC4Crypt class for RC4 encryption
use Breenstorm\SPbusClient\rc4crypt;

/**
 *
 * SPbus Class: PHP Class for controlling Schleifenbauer PDU's
 * @package SPbus
 *
 */
class SPbus
{
    // Private variables
    private $fp;
    private $debugging = false;
    // Control bytes
    private $_tag;
    private $_stx;
    private $_etx;
    private $_ack;
    private $_command;
    // Maximum channel
    private $_channel_max;
    // RC4 key
    private $_rc4_key;
    // Check bytes
    private $_check_bytes_length;
    private $_check_bytes;
    // Checksum length
    private $_checksum_length;
    // Gateway
    private $_gatewayIPAddress;
    private $_gatewayPort;
    // Datamodel
    private $_datamodel;
    // Errors
    private $_errors;
    private $type_pdu_connection; // GATEWAY | SERIAL_PORT | TCP_IP_CONVERTER;
    private $max_retry = 5;

    private  $time_out_connection = 2; // seconds
    private  $time_out_read = 2;

    private $scantimeoutoverall = 1; // seconds, the time that is needed for grabbing a gateway packed

    private $transaction_id = 0;
    private $getting_data_wait = 50000; // 10 milliseconds

    /*
     * Constructor
     *
     * @param -
     * @access public
     * @return -
     *
     */
    public function __construct()
    {

        // Load standard variables with there values
        $this->init();

        // Load datamodel
        $this->_loadDataModel();

        // Load errors
        $this->_loadErrors();
    }

    /*
     * Destructor
     *
     * @param -
     * @access public
     * @return -
     *
     */

    public function __destruct()
    {
        $this->Disconnect();
    }

    public function Disconnect()
    {

        $this->_gatewayIPAddress = "";

        // Close connection
        if (is_resource($this->fp))
        {
            if ($this->debugging == true)
                print "\nClosing Connection\n";
            fclose($this->fp);
        }

        $this->fp = false;
    }

    public function Connect()
    {
        if (!isset($this->_gatewayPort))
        {
            if ($this->debugging == true)
                print "\nError: Port is not set\n";
            return false;
        }

        if ($this->_gatewayPort <= 0)
        {
            if ($this->debugging == true)
                print "\nError: Port is Invalid\n";
            return false;
        }

        if (!isset($this->_gatewayIPAddress))
        {
            if ($this->debugging == true)
                print "\nError: Gateway IP Address is not set\n";
            return false;
        }

        if (strlen($this->_gatewayIPAddress) < 8)
        {
            if ($this->debugging == true)
                print "\nError: gateway Address cannot be shorter than 8 characters\n";
            return false;
        }

        try
        {
            // Close any open connections
            if ($this->fp)
            {
                if ($this->debugging == true)
                    print "\nClosing Connection\n";
                fclose($this->fp);
            }

            // Open connection
            $this->fp = @pfsockopen($this->_gatewayIPAddress, $this->_gatewayPort, $err_no, $err_str, $this->time_out_connection);

            if($this->fp != FALSE)
            {
                // Set a litle timeout of the created connection
                stream_set_timeout($this->fp, $this->time_out_read);
                stream_set_blocking ($this->fp, false);
            }

            if ($this->debugging == true)
                print "Socket opened for Gateway ".$this->_gatewayIPAddress."\n";

            return ($this->fp);
        }
        catch (Exception $exc)
        {
            echo $exc->getTraceAsString();
        }

        // Something went wrong
        return NULL;
    }

    /**
     * Load the standard variables with their values
     *
     */
    private function init()
    {
        // Define control bytes
        $this->_tag = "SAPI";
        $this->_stx = 2;
        $this->_etx = 3;
        $this->_ack = 6;
        $this->_command = array();
        $this->_command['read'] = 1;
        $this->_command['write'] = 16;
        $this->_command['renumber'] = 32;
        $this->_command['scan'] = 144;
        $this->_command['alert_scan'] = 145;
        $this->_command['broadcast_write'] = 160;
        $this->_command['prepare_upgrade'] = 161;
        $this->_command['broadcast_upload_firmware'] = 162;

        // Define channel max
        //$this->_channel_max = 27;
        $this->_channel_max = 54;

        // Define RC4 key
        $this->_rc4_key = "2937630192384732";

        // Define check bytes based on RC4 key
        $this->_check_bytes_length = 4;
        $this->_check_bytes = substr($this->_rc4_key, 0, $this->_check_bytes_length);

        // Define checksum length
        $this->_checksum_length = 4;

        // Gateway
        $this->_gatewayIPAddress = 0;
        $this->_gatewayPort = 0;

        $this->type_pdu_connection = "GATEWAY";
    }

    /**
     *
     * Load errors
     *
     * @param -
     * @access private
     * @return -
     *
     */
    private function _loadErrors()
    {
        // Errors file
        $errors_file = dirname(__FILE__)."/errors";

        // Make sure errors file exist
        if (!file_exists($errors_file))
        {

            if ($this->debugging == true)
                print "\nFile $error_file does not exist\n";
            return FALSE;
        }

        // Load errors
        $errors = file($errors_file, FILE_IGNORE_NEW_LINES);
        $errors_total = sizeof($errors);

        for ($i = 0; $i < $errors_total; $i++)
        {

            $error = $errors[$i];

            list($code, $source, $message) = explode("|", $error);

            $this->_errors[$code]['source'] = $source;
            $this->_errors[$code]['message'] = $message;
        }

        return TRUE;
    }

    /**
     *
     * Load datamodel
     *
     * @param -
     * @access private
     * @return -
     *
     */
    private function _loadDataModel()
    {

        // Datamodel file
        //$datamodel_file = sprintf("%s/datamodel", __DIR__);
        $datamodel_file = dirname(__FILE__)."/datamodel";


        // Make sure datamodel file exists
        if (!file_exists($datamodel_file))
        {

            return FALSE;
        }

        // Load datamodel
        $datamodel = file($datamodel_file, FILE_IGNORE_NEW_LINES);
        $datamodel_total = sizeof($datamodel);

        for ($i = 0; $i < $datamodel_total; $i++)
        {

            $data = $datamodel[$i];

            list($name, $group, $description, $address, $size, $channels, $type) = explode("|", $data);

            $this->_datamodel[$name]['name'] = $name;
            $this->_datamodel[$name]['group'] = $group;
            $this->_datamodel[$name]['description'] = $description;
            $this->_datamodel[$name]['address'] = $address;
            $this->_datamodel[$name]['size'] = $size;
            $this->_datamodel[$name]['channels'] = $channels;
            $this->_datamodel[$name]['type'] = $type;
        }

        return TRUE;
    }

    /**
     *
     * Write register
     *
     * @param array $register
     * @param int $offset
     * @param int $pdu_address
     * @param string $data
     * @access private
     * @return string
     *
     */
    public function writeRegister($register, $offset, $pdu_address, $data)
    {
        // Variables
        $this->transaction_id++;

        // Pack data
        $data = $this->_packByRegisterName($register['name'], $data);

        // if the offset is bigger than 27, than the command will +1
        $command = $this->extention_PDU($this->_command['write'], $offset);

        // Check the offset is bigger than 27
        $offset = $this->check_offset($offset);

        // Construct message (STX byte, command etc)
        $message = pack("C2v4", $this->_stx, $command, $pdu_address, $this->transaction_id,
            ($register['address'] + ($register['size'] * $offset)), $register['size']);

        // Add truncated data to message
        $message .= pack("A{$register['size']}", $data);

        // Calculate CRC checksum
        $crc = $this->_calculateCRC($message);

        // Add CRC to message and add ETX byte
        $message .= pack("vC", $crc, $this->_etx);

        // Start with tag
        $tx_msg = $this->_tag;

        // Add message length
        $tx_msg .= pack("n", ($this->_check_bytes_length + strlen($message) + $this->_checksum_length));

        // Create rc4_msg with check bytes and message
        $rc4_msg = $this->_check_bytes . $message;

        // Add 32-bit checksum to rc4_msg
        $rc4_msg = $rc4_msg . pack("N", $this->_calculateChecksum32bit($rc4_msg));

        // Encrypt rc4_msg and add it to tx_msg
        $tx_msg .= rc4crypt::encrypt($this->_rc4_key, $rc4_msg);

        // Open connection
        //$fp = fsockopen($this->_gatewayIPAddress, $this->_gatewayPort, $err_no, $err_str, 5);

        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging)
            {
                print "Message length: " . strlen($message) . "bytes \n";
            }

            $tx_msg = $message;
        }


        if (!($this->fp))
        {
            if ($this->debugging == true)
                print "\nError in WriteRegister: fp is null\n";
            return FALSE;
        }


        if (fwrite(($this->fp), $tx_msg) === FALSE)
        {
            if ($this->debugging == true)
                print "\nError while writing to output stream\n";
            return FALSE;
        }


        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging == true)
            {
                print "Wait 300 milliseconds\n";
            }
            usleep(300000); //300000
        }

        // TODO what does the gateway return??? We will throw it away for now...
        // Flush input
        $tries = 0;
        $done = false;
        $rx_msg = "";
        $rx_array = array();

        while ((!$done) && ($tries < $this->max_retry))
        {
            $rx_msg .= fread(($this->fp), 1024);

            if ($this->debugging == true)
            {
                var_dump($this->ascii_to_hex($rx_msg));
            }

            $tries++;

            if (strlen($rx_msg) >= 9) // reply to 'write': 9 bytes, reply to failty 'write': 10 bytes
            {
                if ($this->type_pdu_connection == "GATEWAY")
                {
                    $receivedtag = substr($rx_msg, 0, strlen($this->_tag));
                    // Make sure we have the correct tag
                    if ( $receivedtag== $this->_tag)
                    {
                        // Get message length
                        $message_length = implode(unpack("n", substr($rx_msg, strlen($this->_tag), 2)));

                        // Get RC4 part from rx_msg
                        $rc4_msg = substr($rx_msg, (strlen($this->_tag) + 2), 512);

                        // Decrypt rc4_msg
                        $message = rc4crypt::decrypt($this->_rc4_key, $rc4_msg);

                        // Get checksum from message
                        $message_checksum = implode(unpack("N", substr($message, -$this->_checksum_length, $this->_checksum_length)));

                        // Remove checksum from message
                        $message = substr($message, 0, -$this->_checksum_length);

                        // Generate 32-bit for message (without the checksum)
                        $checksum = $this->_calculateChecksum32bit($message);

                        // Make sure message_checksum and checksum are equal
                        if ($message_checksum == $checksum)
                        {
                            // Get check_bytes from message
                            $message_check_bytes = substr($message, 0, $this->_check_bytes_length);

                            // Remove check_bytes from message
                            $data = substr($message, $this->_check_bytes_length, strlen($message));

                            // Make sure check_bytes match
                            if ($message_check_bytes == $this->_check_bytes)
                            {
                                $data = unpack("C*", $data);

                                if(!empty($data) && is_array($data))
                                {
                                    $ACK = $data[1];
                                    $ETX = $data[count($data)];

                                    if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                                    {
                                        $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                                        $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                                        if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                        {
                                            $command = $data[2];
                                            $pdu_address = $data[3] + $data[4] * 256;
                                            $transaction_id = $data[5] + $data[6] * 256;

                                            // Check of the transaction id is the same as the one that is received
                                            if($this->transaction_id == $transaction_id)
                                            {
                                                // transaction id is the same
                                                $done = true;
                                            }
                                        }
                                        else
                                        {
                                            // Not ok
                                            // Raise error -14
                                            if ($this->debugging == true)
                                                print "\nMessage not good recieved\n";
                                        }
                                    }
                                    else
                                    {
                                        // Not ok
                                        // Raise error -14
                                        if ($this->debugging == true)
                                            print "\nMessage not good recieved\n";
                                    }
                                }
                                else
                                {
                                    // No array
                                    if ($this->debugging == true)
                                        print "\nNo array created from the data\n";
                                }
                            }
                            else
                            {
                                // Raise error -14
                                if ($this->debugging == true)
                                    print "\nInvalid Check Bytes\n";
                            }
                        }
                        else
                        {
                            print "\nInvalid Checksum: Received $message_checksum, expected $checksum\n";
                        }
                    }
                    else
                    {
                        // Raise error -11
                        if ($this->debugging == true)
                            print "\nInvalid Tag: expected $this->_tag but received $receivedtag\n";
                    }
                }
                elseif (($this->type_pdu_connection == "TCP_IP_CONVERTER"))
                {
                    $data = unpack("C*", $rx_msg);

                    if(!empty($data) && is_array($data))
                    {
                        $ACK = $data[1];
                        $ETX = $data[count($data)];

                        if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                        {
                            $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                            {
                                $command = $data[2];
                                $pdu_address = $data[3] + $data[4] * 256;
                                $transaction_id = $data[5] + $data[6] * 256;

                                // Check of the transaction id is the same as the one that is received
                                if($this->transaction_id == $transaction_id)
                                {
                                    // transaction id is the same
                                    $done = true;
                                }
                            }
                            else
                            {
                                // Not ok
                                // Raise error -14
                                if ($this->debugging == true)
                                    print "\nMessage not good recieved\n";
                            }
                        }
                        else
                        {
                            // Not ok
                            // Raise error -14
                            if ($this->debugging == true)
                                print "\nMessage not good recieved\n";
                        }
                    }
                    else
                    {
                        // No array
                        if ($this->debugging == true)
                            print "\nNo array created from the data\n";
                    }
                }
            }
            else
            {
                usleep($this->getting_data_wait);
                //usleep(100000); //100ms
            }
        }



        // If the correct message has correct return: return true
        if($done == true)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     *
     * Write register
     *
     * @author mbartels / LaunchIT
     *
     * @param int $register_address,  The base address of a register
     * @param int $register_size,    The size of a compleet pice information
     * @param int $pdu_address,      The pysical address of a PDU
     * @param string $data,          The data that will be written in the register
     * @param int $data_type,        The type of data that will be written (0,1,2)
     * @access public
     * @return boolean
     *
     */
    public function RawWrite($start, $length, $pdu_address, $data, $data_type, $level = 1)
    {
        //$this->debugging = TRUE;

        // Variables
        $this->transaction_id++;

        // Check if the input value are correct
        if (isset($start) && isset($length) && isset($pdu_address))
        {
            $packed_data = null;

            //datatype
            //0 = int (unsigned integer, little-endian, lb - hb)
            //1 = fd (signed fixed decimal, value x 10)
            //2 = ascii
            switch ($data_type)
            {
                case '0':
                    // Pack data
                    $packed_data = $this->_packByDataType('int', $data, $length);
                    break;
                case '1':
                    // Pack data
                    $packed_data = $this->_packByDataType('fd', $data, $length);
                    break;
                case '2':
                    // Pack data
                    $packed_data = $this->_packByDataType('ascii', $data, $length);
                    break;
            }


            if (empty($packed_data))
            {
                if ($this->debugging == true)
                    print "\nError data is not packed\n";
                return FALSE;
            }

            $command = $this->_command['write'];

            if($level == 2)
            {
                $command = $this->_command['write'] + 1;
            }


            // Construct message (STX byte, command etc)
            $message = pack("C2v4",
                $this->_stx,
                $command,
                $pdu_address,
                $this->transaction_id,
                $start,
                $length);

            // Add truncated data to message
            $message .= pack("A{$length}", $packed_data);

            // Calculate CRC checksum
            $crc = $this->_calculateCRC($message);

            // Add CRC to message and add ETX byte
            $message .= pack("vC", $crc, $this->_etx);

            // Start with tag
            $tx_msg = $this->_tag;

            // Add message length
            $tx_msg .= pack("n", ($this->_check_bytes_length + strlen($message) + $this->_checksum_length));

            // Create rc4_msg with check bytes and message
            $rc4_msg = $this->_check_bytes . $message;

            // Add 32-bit checksum to rc4_msg
            $rc4_msg = $rc4_msg . pack("N", $this->_calculateChecksum32bit($rc4_msg));

            // Encrypt rc4_msg and add it to tx_msg
            $tx_msg .= rc4crypt::encrypt($this->_rc4_key, $rc4_msg);

            // Open connection
            //$fp = fsockopen($this->_gatewayIPAddress, $this->_gatewayPort, $err_no, $err_str, 5);


            if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
            {
                if ($this->debugging)
                {
                    print "Message length: " . strlen($message) . "bytes \n";
                }

                $tx_msg = $message;
            }


            if (!($this->fp))
            {
                if ($this->debugging == true)
                    print "\nError in WriteRegister: fp is null\n";
                return FALSE;
            }


            if (fwrite(($this->fp), $tx_msg) === FALSE)
            {
                if ($this->debugging == true)
                    print "\nError while writing to output stream\n";
                return FALSE;
            }


            if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
            {
                if ($this->debugging == true)
                {
                    print "Wait 300 milieseconds\n";
                }
                usleep(300000); //300000
            }

            // Read response

            $tries = 0;
            $done = false;
            $rx_msg = "";
            $rx_array = array();

            while ((!$done) && ($tries < $this->max_retry))
            {
                $rx_msg .= fread(($this->fp), 1024);

                if ($this->debugging == true)
                {
                    echo $this->ascii_to_hex($rx_msg);
                }

                $tries++;

                if (strlen($rx_msg) >= 9) // reply to 'write': 9 bytes, reply to failty 'write': 10 bytes
                {
                    if ($this->type_pdu_connection == "GATEWAY")
                    {
                        $receivedtag = substr($rx_msg, 0, strlen($this->_tag));
                        // Make sure we have the correct tag
                        if ( $receivedtag== $this->_tag)
                        {
                            // Get message length
                            $message_length = implode(unpack("n", substr($rx_msg, strlen($this->_tag), 2)));

                            // Get RC4 part from rx_msg
                            $rc4_msg = substr($rx_msg, (strlen($this->_tag) + 2), 512);

                            // Decrypt rc4_msg
                            $message = rc4crypt::decrypt($this->_rc4_key, $rc4_msg);

                            // Get checksum from message
                            $message_checksum = implode(unpack("N", substr($message, -$this->_checksum_length, $this->_checksum_length)));

                            // Remove checksum from message
                            $message = substr($message, 0, -$this->_checksum_length);

                            // Generate 32-bit for message (without the checksum)
                            $checksum = $this->_calculateChecksum32bit($message);

                            // Make sure message_checksum and checksum are equal
                            if ($message_checksum == $checksum)
                            {
                                // Get check_bytes from message
                                $message_check_bytes = substr($message, 0, $this->_check_bytes_length);

                                // Remove check_bytes from message
                                $data = substr($message, $this->_check_bytes_length, strlen($message));

                                // Make sure check_bytes match
                                if ($message_check_bytes == $this->_check_bytes)
                                {
                                    $data = unpack("C*", $data);

                                    if(!empty($data) && is_array($data))
                                    {
                                        $ACK = $data[1];
                                        $ETX = $data[count($data)];

                                        if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                                        {
                                            $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                                            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                                            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                            {
                                                $command = $data[2];
                                                $pdu_address = $data[3] + $data[4] * 256;
                                                $transaction_id = $data[5] + $data[6] * 256;

                                                // Check of the transaction id is the same as the one that is received
                                                if($this->transaction_id == $transaction_id)
                                                {
                                                    // transaction id is the same
                                                    $done = true;
                                                }
                                            }
                                            else
                                            {
                                                // Not ok
                                                if ($this->debugging == true)
                                                {
                                                    print "\nMessage not good recieved\n";
                                                }
                                            }
                                        }
                                        else
                                        {
                                            // Not ok
                                            if ($this->debugging == true)
                                            {
                                                $this->print_error($data[1]);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        // No array
                                        if ($this->debugging == true)
                                        {
                                            print "\nNo array created from the data\n";
                                        }
                                    }
                                }
                                else
                                {
                                    // Raise error -14
                                    if ($this->debugging == true)
                                    {
                                        print "\nInvalid Check Bytes\n";
                                    }
                                }
                            }
                            else
                            {
                                //
                                if ($this->debugging == true)
                                {
                                    print "\nInvalid Checksum: Received $message_checksum, expected $checksum\n";
                                }
                            }
                        }
                        else
                        {
                            // Raise error -11
                            if ($this->debugging == true)
                            {
                                print "\nInvalid Tag: expected $this->_tag but received $receivedtag\n";
                            }
                        }
                    }
                    elseif (($this->type_pdu_connection == "TCP_IP_CONVERTER"))
                    {
                        $data = unpack("C*", $rx_msg);

                        if(!empty($data) && is_array($data))
                        {
                            $ACK = $data[1];
                            $ETX = $data[count($data)];

                            if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                            {
                                $CRC = $data[count($data) - 2] +  $data[count($data) -1] * 256;

                                $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                                if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                {
                                    $command = $data[2];
                                    $pdu_address = $data[3] + $data[4] * 256;
                                    $transaction_id = $data[5] + $data[6] * 256;

                                    // Check of the transaction id is the same as the one that is received
                                    if($this->transaction_id == $transaction_id)
                                    {
                                        // transaction id is the same
                                        $done = true;
                                    }
                                }
                                else
                                {
                                    // Not ok
                                    // Raise error -14
                                    if ($this->debugging == true)
                                        print "\nRecieved message is not good\n";
                                }
                            }
                            else
                            {
                                // Not ok
                                if ($this->debugging == true)
                                {
                                    $this->print_error($data[1]);
                                }
                            }
                        }
                        else
                        {
                            // No array
                            if ($this->debugging == true)
                                print "\nNo array created from the data\n";
                        }
                    }
                }
                else
                {
                    //usleep(100000); //100ms
                    usleep($this->getting_data_wait);
                }
            }


            if($done == TRUE)
            {
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
        else
        {
            return FALSE;
        }
    }

    /**
     *
     * Write register
     *
     * @author mbartels / LaunchIT
     *
     * @param int $register_address,  The base address of a register
     * @param int $register_size,    The size of a compleet pice information
     * @param int $pdu_address,      The pysical address of a PDU
     * @param string $data,          The data that will be written in the register
     * @param int $data_type,        The type of data that will be written (0,1,2)
     * @access public
     * @return boolean
     *
     */
    public function RawWriteRenumber($hardware_address_array, $new_pdu_address)
    {
        // Check if the input value are correct
        if (isset($hardware_address_array) && !empty($hardware_address_array) && is_array($hardware_address_array) && isset($new_pdu_address) & !empty($new_pdu_address))
        {
            $packed_data = null;

            $command = $this->_command['renumber'];


            // Packed the front of the message
            $message = pack("C2",
                $this->_stx,
                $command);


            // Packed serial number
            $hardware_address_packed = NULL;
            $hardware_address_string = "";
            foreach($hardware_address_array as $hardware_address)
            {
                $hardware_address_packed .= pack('v', $hardware_address);
                $hardware_address_string .= $hardware_address;
            }

            // Packed new PDU address
            $packed_address = pack('v', $new_pdu_address);


            $message .= $hardware_address_packed.$packed_address;


            // Calculate CRC checksum
            $crc = $this->_calculateCRC($message);

            // Add CRC to message and add ETX byte
            $message .= pack("vC", $crc, $this->_etx);

            // Start with tag
            $tx_msg = $this->_tag;

            // Add message length
            $tx_msg .= pack("n", ($this->_check_bytes_length + strlen($message) + $this->_checksum_length));

            // Create rc4_msg with check bytes and message
            $rc4_msg = $this->_check_bytes . $message;

            // Add 32-bit checksum to rc4_msg
            $rc4_msg = $rc4_msg . pack("N", $this->_calculateChecksum32bit($rc4_msg));

            // Encrypt rc4_msg and add it to tx_msg
            $tx_msg .= rc4crypt::encrypt($this->_rc4_key, $rc4_msg);

            // Open connection
            //$fp = fsockopen($this->_gatewayIPAddress, $this->_gatewayPort, $err_no, $err_str, 5);


            if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
            {
                if ($this->debugging)
                {
                    print "Message length: " . strlen($message) . "bytes \n";
                }

                $tx_msg = $message;
            }


            if (!($this->fp))
            {
                if ($this->debugging == true)
                    print "\nError in WriteRegister: fp is null\n";
                return FALSE;
            }


            if (fwrite(($this->fp), $tx_msg) === FALSE)
            {
                if ($this->debugging == true)
                    print "\nError while writing to output stream\n";
                return FALSE;
            }


            if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
            {
                if ($this->debugging == true)
                {
                    print "Wait 300 milieseconds\n";
                }
                usleep(300000); //300000
            }

            // Read response

            $tries = 0;
            $done = false;
            $rx_msg = "";
            $rx_array = array();

            while ((!$done) && ($tries < $this->max_retry))
            {
                $rx_msg .= fread(($this->fp), 1024);

                if ($this->debugging == true)
                {
                    echo $this->ascii_to_hex($rx_msg);
                }

                $tries++;

                if (strlen($rx_msg) >= 9) // reply to 'write': 9 bytes, reply to failty 'write': 10 bytes
                {
                    $time_start = microtime(true);

                    if ($this->type_pdu_connection == "GATEWAY")
                    {
                        $receivedtag = substr($rx_msg, 0, strlen($this->_tag));
                        // Make sure we have the correct tag
                        if ( $receivedtag== $this->_tag)
                        {
                            // Get message length
                            $message_length = implode(unpack("n", substr($rx_msg, strlen($this->_tag), 2)));

                            // Get RC4 part from rx_msg
                            $rc4_msg = substr($rx_msg, (strlen($this->_tag) + 2), 512);

                            // Decrypt rc4_msg
                            $message = rc4crypt::decrypt($this->_rc4_key, $rc4_msg);

                            // Get checksum from message
                            $message_checksum = implode(unpack("N", substr($message, -$this->_checksum_length, $this->_checksum_length)));

                            // Remove checksum from message
                            $message = substr($message, 0, -$this->_checksum_length);

                            // Generate 32-bit for message (without the checksum)
                            $checksum = $this->_calculateChecksum32bit($message);

                            // Make sure message_checksum and checksum are equal
                            if ($message_checksum == $checksum)
                            {
                                // Get check_bytes from message
                                $message_check_bytes = substr($message, 0, $this->_check_bytes_length);

                                // Remove check_bytes from message
                                $data = substr($message, $this->_check_bytes_length, strlen($message));

                                // Make sure check_bytes match
                                if ($message_check_bytes == $this->_check_bytes)
                                {
                                    $data = unpack("C*", $data);

                                    if(!empty($data) && is_array($data))
                                    {
                                        $ACK = $data[1];
                                        $ETX = $data[count($data)];

                                        if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                                        {
                                            $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                                            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                                            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                            {
                                                $command = $data[2];
                                                $_hardware_address = ($data[3] + $data[4] * 256).($data[5] + $data[6] * 256).($data[7] + $data[8] * 256);


                                                if($_hardware_address == $hardware_address_string)
                                                {
                                                    $done = true;
                                                }
                                                else
                                                {
                                                    // Not ok
                                                    if ($this->debugging == true)
                                                    {
                                                        print "\nMessage is from other PDU. Hardware address is not the same\n";
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                // Not ok
                                                if ($this->debugging == true)
                                                {
                                                    print "\nMessage not good recieved\n";
                                                }
                                            }
                                        }
                                        else
                                        {
                                            // Not ok
                                            if ($this->debugging == true)
                                            {
                                                $this->print_error($data[1]);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        // No array
                                        if ($this->debugging == true)
                                        {
                                            print "\nNo array created from the data\n";
                                        }
                                    }
                                }
                                else
                                {
                                    // Raise error -14
                                    if ($this->debugging == true)
                                    {
                                        print "\nInvalid Check Bytes\n";
                                    }
                                }
                            }
                            else
                            {
                                //
                                if ($this->debugging == true)
                                {
                                    print "\nInvalid Checksum: Received $message_checksum, expected $checksum\n";
                                }
                            }
                        }
                        else
                        {
                            // Raise error -11
                            if ($this->debugging == true)
                            {
                                print "\nInvalid Tag: expected $this->_tag but received $receivedtag\n";
                            }
                        }
                    }
                    elseif (($this->type_pdu_connection == "TCP_IP_CONVERTER"))
                    {
                        $data = unpack("C*", $rx_msg);

                        if(!empty($data) && is_array($data))
                        {
                            $ACK = $data[1];
                            $ETX = $data[count($data)];

                            if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                            {
                                $CRC = $data[count($data) - 2] +  $data[count($data) -1] * 256;

                                $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                                if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                {
                                    $command = $data[2];
                                    $_hardware_address = ($data[3] + $data[4] * 256).($data[5] + $data[6] * 256).($data[7] + $data[8] * 256);


                                    if($_hardware_address == $hardware_address_string)
                                    {
                                        $done = true;
                                    }
                                    else
                                    {
                                        // Not ok
                                        if ($this->debugging == true)
                                        {
                                            print "\nMessage is from other PDU. Hardware address is not the same\n";
                                        }
                                    }
                                }
                                else
                                {
                                    // Not ok
                                    // Raise error -14
                                    if ($this->debugging == true)
                                        print "\nRecieved message is not ok\n";
                                }
                            }
                            else
                            {
                                // Not ok
                                if ($this->debugging == true)
                                {
                                    $this->print_error($data[1]);
                                }
                            }
                        }
                        else
                        {
                            // No array
                            if ($this->debugging == true)
                                print "\nNo array created from the data\n";
                        }
                    }
                }
                else
                {
                    usleep($this->getting_data_wait);
                    //usleep(100000); //100ms
                }
            }


            if($done == TRUE)
            {
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
        else
        {
            return FALSE;
        }
    }
    /**
     *
     * AlertScan Bus
     * @author Ben Vaessen / Launch IT
     * @return A list of IDs found
     */
    public function AlertScanBus()
    {
        if ($this->debugging == true)
            print "\nStarted Alert Scan\n";

        // Construct message (STX byte, command etc)
        $message = pack("C2", $this->_stx, $this->_command['alert_scan']);

        // Calculate CRC checksum
        $crc = $this->_calculateCRC($message);

        // Add CRC to message and add ETX byte
        $message .= pack("vC", $crc, $this->_etx);

        // Start with tag
        $tx_msg = $this->_tag;

        // Add message length
        $tx_msg .= pack("n", ($this->_check_bytes_length + strlen($message) + $this->_checksum_length));

        // Create rc4_msg with check bytes and message
        $rc4_msg = $this->_check_bytes . $message;

        // Add 32-bit checksum to rc4_msg
        $rc4_msg = $rc4_msg . pack("N", $this->_calculateChecksum32bit($rc4_msg));

        // Encrypt rc4_msg and add it to tx_msg
        $tx_msg .= rc4crypt::encrypt($this->_rc4_key, $rc4_msg);


        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging)
            {
                print "Message length: " . strlen($message) . "bytes \n";
            }

            $tx_msg = $message;
        }

        // Open connection
        //$fp = fsockopen($this->_gatewayIPAddress, $this->_gatewayPort, $err_no, $err_str, 5);
        // Check for connection errors
        if (!($this->fp))
        {
            // raiseError($err_str, $err_no);
            if ($this->debugging == true)
                print "\nCannot Scan: FP is null\n";
            return FALSE;
        }

        // Write command, check for errors
        if (fwrite(($this->fp), $tx_msg) === FALSE)
        {
            // raiseError()
            if ($this->debugging == true)
                print "\nError while writing scan message\n";
            return FALSE;
        }

        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging == true)
            {
                print "Wait 300 milieseconds\n";
            }
            usleep(300000); //300000
        }

        $time_start = microtime(true);
        $time_now = microtime(true);
        $time = $time_now - $time_start;

        $found_ids = array();
        $n_found = 0;
        $rx_array = array();
        $get_return_message = FALSE;

        stream_set_timeout(($this->fp), $this->time_out_read);


        while ($time < $this->scantimeoutoverall)
        {
            // Read response
            $rx_msg = fread(($this->fp), 1024);

            if(!empty($rx_msg))
            {
                if ($this->debugging == true)
                {
                    echo "RECEIVED:" . $this->ascii_to_hex($rx_msg);
                }

                if ($this->type_pdu_connection == "GATEWAY")
                {
                    $receivedtag = substr($rx_msg, 0, strlen($this->_tag));
                    // Make sure we have the correct tag
                    if (substr($rx_msg, 0, strlen($this->_tag)) == $this->_tag)
                    {
                        // Get message length
                        $message_length = implode(unpack("n", substr($rx_msg, strlen($this->_tag), 2)));

                        // Get RC4 part from rx_msg
                        $rc4_msg = substr($rx_msg, (strlen($this->_tag) + 2), 512);

                        // Decrypt rc4_msg
                        $message = rc4crypt::decrypt($this->_rc4_key, $rc4_msg);

                        // Get checksum from message
                        $message_checksum = implode(unpack("N", substr($message, -$this->_checksum_length, $this->_checksum_length)));

                        // Remove checksum from message
                        $message = substr($message, 0, -$this->_checksum_length);

                        // Generate 32-bit for message (without the checksum)
                        $checksum = $this->_calculateChecksum32bit($message);

                        // Make sure message_checksum and checksum are equal
                        if ($message_checksum == $checksum)
                        {
                            // Get check_bytes from message
                            $message_check_bytes = substr($message, 0, $this->_check_bytes_length);

                            // Remove check_bytes from message
                            $data = substr($message, $this->_check_bytes_length, strlen($message));

                            // Make sure check_bytes match
                            if ($message_check_bytes == $this->_check_bytes)
                            {
                                if ($this->debugging == true)
                                {
                                    echo "RECEIVED:" . $this->ascii_to_hex($data);
                                }

                                $time_start = microtime(true);

                                $data = unpack("C*", $data);

                                if(!empty($data) && is_array($data))
                                {
                                    // The $data is one big array where all the messages data will be stored.
                                    // One PDU scan message is 13 bytes long.
                                    // Split array in pices of 13 bytes
                                    $result_array = array_chunk($data, 13);

                                    foreach ($result_array as $rx_array)
                                    {
                                        if (count($rx_array) == 13)
                                        {
                                            $end_index = count($rx_array) - 1;
                                            $ACK = $rx_array[0];
                                            $status = $rx_array[4];
                                            $ETX = $rx_array[$end_index];
                                            $CRC = $rx_array[$end_index - 2] +  $rx_array[$end_index -1] * 256;

                                            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($rx_array, 0, $end_index - 2)));

                                            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                            {
                                                if ($status != 0)
                                                {
                                                    $found_ids[$n_found] = $rx_array[2] + $rx_array[3] * 256;
                                                    $n_found++;
                                                }
                                            }
                                            else
                                            {
                                                // Not ok
                                                // Raise error -14
                                                if ($this->debugging == true)
                                                    print "\nReceived message is not ok\n";
                                            }
                                        }
                                        else
                                        {
                                            // Size of datablock is not good
                                            if ($this->debugging == true)
                                                print "\nSize of datablock is not ok\n";
                                        }
                                    }
                                }
                                else
                                {
                                    // No array
                                    if ($this->debugging == true)
                                        print "\nNo array created from the data\n";
                                }
                            }
                            else
                            {
                                // Raise error -14
                                if ($this->debugging == true)
                                    print "\nInvalid Check Bytes\n";
                            }
                        }
                        else
                        {
                            print "\nInvalid Checksum: Received $message_checksum, expected $checksum\n";
                        }
                    }
                    else
                    {
                        // Raise error -11
                        if ($this->debugging == true)
                            print "\nInvalid Tag: expected $this->_tag but received $receivedtag\n";
                    }
                }
                elseif (($this->type_pdu_connection == "TCP_IP_CONVERTER"))
                {
                    $data = unpack("C*", $rx_msg);

                    if(!empty($data) && is_array($data))
                    {
                        // The $data is one big array where all the messages data will be stored.
                        // One PDU scan message is 13 bytes long.
                        // Split array in pices of 13 bytes
                        $result_array = array_chunk($data, 13);

                        foreach ($result_array as $rx_array)
                        {
                            if (count($rx_array) == 13)
                            {
                                $time_start = microtime(true);

                                $end_index = count($rx_array) - 1;
                                $ACK = $rx_array[0];
                                $status = $rx_array[4];
                                $ETX = $rx_array[$end_index];
                                $CRC = $rx_array[$end_index - 2] +  $rx_array[$end_index -1] * 256;

                                $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($rx_array, 0, $end_index - 2)));

                                if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                {
                                    if ($status != 0)
                                    {
                                        $found_ids[$n_found] = $rx_array[2] + $rx_array[3] * 256;
                                        $n_found++;
                                    }
                                }
                                else
                                {
                                    // Not ok
                                    // Raise error -14
                                    if ($this->debugging == true)
                                        print "\nRecieved message is not good\n";
                                }
                            }
                            else
                            {
                                // Size of datablock is not good
                                if ($this->debugging == true)
                                    print "\nSize of datablock is not good\n";
                            }
                        }
                    }
                    else
                    {
                        // No array
                        if ($this->debugging == true)
                            print "\nNo array created from the data\n";
                    }
                }
            }

            //usleep($this->getting_data_wait);

            $time_now = microtime(true);
            $time = $time_now - $time_start;
        }

        // Close connection
        //fclose($fp);

        if ($this->debugging == true)
        {
            print "Found id`s: \n";

            if (!empty($found_ids) && is_array($found_ids))
            {
                foreach ($found_ids as $key => $ids)
                {
                    print " - " . $ids . "\n";
                }
            }
        }

        // Return found IDs
        //var_dump($found_ids);
        return $found_ids;
    }

    /**
     *
     * Scan Bus
     * @author Ben Vaessen / Launch IT
     * @return A list of IDs found
     */
    public function ScanBus()
    {
        if ($this->debugging == true)
            print "\nStarted Scan\n";

        // Construct message (STX byte, command etc)
        $message = pack("C2", $this->_stx, $this->_command['scan']);

        // Calculate CRC checksum
        $crc = $this->_calculateCRC($message);

        // Add CRC to message and add ETX byte
        $message .= pack("vC", $crc, $this->_etx);

        // Start with tag
        $tx_msg = $this->_tag;

        // Add message length
        $tx_msg .= pack("n", ($this->_check_bytes_length + strlen($message) + $this->_checksum_length));

        // Create rc4_msg with check bytes and message
        $rc4_msg = $this->_check_bytes . $message;

        // Add 32-bit checksum to rc4_msg
        $rc4_msg = $rc4_msg . pack("N", $this->_calculateChecksum32bit($rc4_msg));

        // Encrypt rc4_msg and add it to tx_msg
        $tx_msg .= rc4crypt::encrypt($this->_rc4_key, $rc4_msg);


        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging)
            {
                print "Message length: " . strlen($message) . "bytes \n";
            }

            $tx_msg = $message;
        }

        // Open connection
        //$fp = fsockopen($this->_gatewayIPAddress, $this->_gatewayPort, $err_no, $err_str, 5);
        // Check for connection errors
        if (!($this->fp))
        {
            // raiseError($err_str, $err_no);
            if ($this->debugging == true)
                print "\nCannot Scan: FP is null\n";
            return FALSE;
        }

        // Write command, check for errors
        if (fwrite(($this->fp), $tx_msg) === FALSE)
        {
            // raiseError()
            if ($this->debugging == true)
                print "\nError while writing scan message\n";
            return FALSE;
        }

        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging == true)
            {
                print "Wait 300 milieseconds\n";
            }
            usleep(300000); //300000
        }

        $time_start = microtime(true);
        $time_now = microtime(true);
        $time = $time_now - $time_start;

        $found_ids = array();
        $n_found = 0;
        $rx_array = array();
        $get_return_message = FALSE;

        stream_set_timeout(($this->fp), $this->time_out_read);


        while ($time < $this->scantimeoutoverall)
        {
            // Read response
            $rx_msg = fread(($this->fp), 1024);

            if ($this->debugging == true)
            {
                echo $this->ascii_to_hex($rx_msg);
            }

            if(!empty($rx_msg))
            {
                if ($this->type_pdu_connection == "GATEWAY")
                {
                    $receivedtag = substr($rx_msg, 0, strlen($this->_tag));
                    // Make sure we have the correct tag
                    if (substr($rx_msg, 0, strlen($this->_tag)) == $this->_tag)
                    {
                        // Get message length
                        $message_length = implode(unpack("n", substr($rx_msg, strlen($this->_tag), 2)));

                        // Get RC4 part from rx_msg
                        $rc4_msg = substr($rx_msg, (strlen($this->_tag) + 2), 512);

                        // Decrypt rc4_msg
                        $message = rc4crypt::decrypt($this->_rc4_key, $rc4_msg);

                        // Get checksum from message
                        $message_checksum = implode(unpack("N", substr($message, -$this->_checksum_length, $this->_checksum_length)));

                        // Remove checksum from message
                        $message = substr($message, 0, -$this->_checksum_length);

                        // Generate 32-bit for message (without the checksum)
                        $checksum = $this->_calculateChecksum32bit($message);

                        // Make sure message_checksum and checksum are equal
                        if ($message_checksum == $checksum)
                        {
                            // Get check_bytes from message
                            $message_check_bytes = substr($message, 0, $this->_check_bytes_length);

                            // Remove check_bytes from message
                            $data = substr($message, $this->_check_bytes_length, strlen($message));

                            // Make sure check_bytes match
                            if ($message_check_bytes == $this->_check_bytes)
                            {
                                $data = unpack("C*", $data);

                                if(!empty($data) && is_array($data))
                                {
                                    // The $data is one big array where all the messages data will be stored.
                                    // One PDU scan message is 13 bytes long.
                                    // Split array in pices of 13 bytes
                                    $result_array = array_chunk($data, 13);

                                    foreach ($result_array as $rx_array)
                                    {
                                        if (count($rx_array) == 13)
                                        {
                                            $end_index = count($rx_array) - 1;
                                            $ACK = $rx_array[0];
                                            $ETX = $rx_array[$end_index];
                                            $CRC = $rx_array[$end_index - 2] +  $rx_array[$end_index -1] * 256;

                                            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($rx_array, 0, $end_index - 2)));

                                            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                            {
                                                $found_ids[$n_found] = $rx_array[2] + $rx_array[3] * 256;
                                                $n_found++;
                                            }
                                            else
                                            {
                                                // Not ok
                                                // Raise error -14
                                                if ($this->debugging == true)
                                                    print "\nRecieved message is not good\n";
                                            }
                                        }
                                        else
                                        {
                                            // Size of datablock is not good
                                            if ($this->debugging == true)
                                                print "\nSize of datablock is not good\n";
                                        }
                                    }
                                }
                                else
                                {
                                    // No array
                                    if ($this->debugging == true)
                                        print "\nNo array created from the data\n";
                                }
                            }
                            else
                            {
                                // Raise error -14
                                if ($this->debugging == true)
                                    print "\nInvalid Check Bytes\n";
                            }
                        }
                        else
                        {
                            print "\nInvalid Checksum: Received $message_checksum, expected $checksum\n";
                        }
                    }
                    else
                    {
                        // Raise error -11
                        if ($this->debugging == true)
                            print "\nInvalid Tag: expected $this->_tag but received $receivedtag\n";
                    }
                }
                elseif (($this->type_pdu_connection == "TCP_IP_CONVERTER"))
                {
                    $data = unpack("C*", $rx_msg);

                    if(!empty($data) && is_array($data))
                    {
                        // The $data is one big array where all the messages data will be stored.
                        // One PDU scan message is 13 bytes long.
                        // Split array in pices of 13 bytes
                        $result_array = array_chunk($data, 13);

                        foreach ($result_array as $rx_array)
                        {
                            if (count($rx_array) == 13)
                            {
                                $end_index = count($rx_array) - 1;
                                $ACK = $rx_array[0];
                                $ETX = $rx_array[$end_index];
                                $CRC = $rx_array[$end_index - 2] +  $rx_array[$end_index -1] * 256;

                                $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($rx_array, 0, $end_index - 2)));

                                if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                {
                                    $found_ids[$n_found] = $rx_array[2] + $rx_array[3] * 256;
                                    $n_found++;
                                }
                                else
                                {
                                    // Not ok
                                    // Raise error -14
                                    if ($this->debugging == true)
                                        print "\nRecieved message is not good\n";
                                }
                            }
                            else
                            {
                                // Size of datablock is not good
                                if ($this->debugging == true)
                                    print "\nSize of datablock is not good\n";
                            }
                        }
                    }
                    else
                    {
                        // No array
                        if ($this->debugging == true)
                            print "\nNo array created from the data\n";
                    }
                }
            }

            //usleep($this->getting_data_wait);

            $time_now = microtime(true);
            $time = $time_now - $time_start;
        }

        // Close connection
        //fclose($fp);

        if ($this->debugging == true)
        {
            print "Found id`s: \n";

            if (!empty($found_ids) && is_array($found_ids))
            {
                foreach ($found_ids as $key => $ids)
                {
                    print " - " . $ids . "\n";
                }
            }
        }

        // Return found IDs
        //var_dump($found_ids);
        return $found_ids;
    }

    /**
     *
     * Read register
     *
     * @param array $register
     * @param int $ofsset
     * @param int $pdu_address
     * @access private
     * @return string
     *
     */
    public function ReadRaw($start, $length, $pdu_address, $level = 1)
    {
        if ($this->debugging)
            print "\nReading $length bytes starting at register $start, on PDU $pdu_address\n";

        // Variables
        $this->transaction_id++;


        if($level == 2)
        {
            $command = $this->_command['read'] + 1;
        }
        else
        {
            $command = $this->_command['read'];
        }

        // Construct message (STX byte, command etc)
        $message = pack("C2v4", $this->_stx, $command, $pdu_address, $this->transaction_id,
            $start, $length);

        // Calculate CRC checksum
        $crc = $this->_calculateCRC($message);

        // Add CRC to message and add ETX byte
        $message .= pack("vC", $crc, $this->_etx);

        // Start with tag
        $tx_msg = $this->_tag;

        // Add message length
        $tx_msg .= pack("n", ($this->_check_bytes_length + strlen($message) + $this->_checksum_length));

        // Create rc4_msg with check bytes and message
        $rc4_msg = $this->_check_bytes . $message;

        // Add 32-bit checksum to rc4_msg
        $rc4_msg = $rc4_msg . pack("N", $this->_calculateChecksum32bit($rc4_msg));

        // Encrypt rc4_msg and add it to tx_msg
        $tx_msg .= rc4crypt::encrypt($this->_rc4_key, $rc4_msg);



        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging)
            {
                print "Message length: " . strlen($message) . "bytes \n";
            }

            $tx_msg = $message;
        }

        // Check for connection errors
        if (!($this->fp))
        {
            // raiseError($err_str, $err_no);
            if ($this->debugging == true)
                print "\nCannot Read Register: fp is null\n";
            return FALSE;
        }

        // Write command, check for errors
        if (fwrite(($this->fp), $tx_msg) === FALSE)
        {
            // raiseError()
            if ($this->debugging == true)
                print "\nCannot write read message\n";
            return FALSE;
        }


        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging == true)
            {
                print "Wait 300 milliseconds\n";
            }
            usleep(300000); //300000
        }

        // Read response

        $tries = 0;
        $done = false;
        $rx_msg = "";
        $rx_array = array();
        $return_data = array();

        stream_set_timeout(($this->fp), $this->time_out_read);

        while ((!$done) && ($tries < $this->max_retry))
        {
            $rx_msg .= fread(($this->fp), 1024);

            if ($this->debugging == true)
            {
                var_dump($this->ascii_to_hex($rx_msg));
            }

            $tries++;

            if (strlen($rx_msg) >= 13 + $length)
            {
                if ($this->type_pdu_connection == "GATEWAY")
                {
                    $receivedtag = substr($rx_msg, 0, strlen($this->_tag));

                    // Make sure we have the correct tag
                    if ( $receivedtag== $this->_tag)
                    {
                        // Get message length
                        $message_length = implode(unpack("n", substr($rx_msg, strlen($this->_tag), 2)));

                        // Get RC4 part from rx_msg
                        $rc4_msg = substr($rx_msg, (strlen($this->_tag) + 2), 512);

                        // Decrypt rc4_msg
                        $message = rc4crypt::decrypt($this->_rc4_key, $rc4_msg);

                        // Get checksum from message
                        $message_checksum = implode(unpack("N", substr($message, -$this->_checksum_length, $this->_checksum_length)));

                        // Remove checksum from message
                        $message = substr($message, 0, -$this->_checksum_length);

                        // Generate 32-bit for message (without the checksum)
                        $checksum = $this->_calculateChecksum32bit($message);

                        // Make sure message_checksum and checksum are equal
                        if ($message_checksum == $checksum)
                        {
                            // Get check_bytes from message
                            $message_check_bytes = substr($message, 0, $this->_check_bytes_length);

                            // Remove check_bytes from message
                            $data = substr($message, $this->_check_bytes_length, strlen($message));


                            // Make sure check_bytes match
                            if ($message_check_bytes == $this->_check_bytes)
                            {
                                $data = unpack("C*", $data);

                                if(!empty($data) && is_array($data))
                                {
                                    $ACK = $data[1];
                                    $ETX = $data[count($data)];

                                    if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                                    {
                                        $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                                        $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                                        if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                        {
                                            $command = $data[2];
                                            $pdu_address = $data[3] + $data[4] * 256;
                                            $transaction_id = $data[5] + $data[6] * 256;

                                            $register_start = $data[7] + $data[8] * 256;
                                            $register_length = $data[9] + $data[10] * 256;

                                            // Check of the transaction id is the same as the one that is received
                                            if($this->transaction_id == $transaction_id)
                                            {
                                                // Slice the $rx_array from the 10th position with the length of the $register_length
                                                // The result is an array of data
                                                $result_data = array_slice($data, 10, $length);

                                                // Convert the array to a string of bytes
                                                $return_data = $this->array_to_ascii($result_data);

                                                // transaction id is the same
                                                $done = true;
                                            }
                                        }
                                        else
                                        {
                                            // Not ok
                                            // Raise error -14
                                            if ($this->debugging == true)
                                                print "\nRecieved message is not good\n";
                                        }
                                    }
                                    else
                                    {
                                        // Not ok
                                        // Raise error -14
                                        if ($this->debugging == true)
                                            print "\nRecieved message is not good\n";
                                    }
                                }
                                else
                                {
                                    // No array
                                    if ($this->debugging == true)
                                        print "\nNo array created from the data\n";
                                }
                            }
                            else
                            {
                                // Raise error -14
                                if ($this->debugging == true)
                                    print "\nInvalid Check Bytes\n";
                            }
                        }
                        else
                        {
                            print "\nInvalid Checksum: Received $message_checksum, expected $checksum\n";
                        }
                    }
                    else
                    {
                        // Raise error -11
                        if ($this->debugging == true)
                            print "\nInvalid Tag: expected $this->_tag but received $receivedtag\n";
                    }
                }
                elseif (($this->type_pdu_connection == "TCP_IP_CONVERTER"))
                {
                    $data = unpack("C*", $rx_msg);

                    if(!empty($data) && is_array($data))
                    {
                        $ACK = $data[1];
                        $ETX = $data[count($data)];

                        if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                        {
                            $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                            {
                                $command = $data[2];
                                $pdu_address = $data[3] + $data[4] * 256;
                                $transaction_id = $data[5] + $data[6] * 256;

                                $register_start = $data[7] + $data[8] * 256;
                                $register_length = $data[9] + $data[10] * 256;

                                // Check of the transaction id is the same as the one that is received
                                if($this->transaction_id == $transaction_id)
                                {
                                    // Slice the $rx_array from the 10th position with the length of the $register_length
                                    // The result is an array of data
                                    $result_data = array_slice($data, 10, $length);

                                    // Convert the array to a string of bytes
                                    $return_data = $this->array_to_ascii($result_data);

                                    // transaction id is the same
                                    $done = true;
                                }
                            }
                            else
                            {
                                // Not ok
                                // Raise error -14
                                if ($this->debugging == true)
                                    print "\nRecieved message is not good\n";
                            }
                        }
                        else
                        {
                            // Not ok
                            // Raise error -14
                            if ($this->debugging == true)
                                print "\nRecieved message is not good\n";
                        }
                    }
                    else
                    {
                        // No array
                        if ($this->debugging == true)
                            print "\nNo array created from the data\n";
                    }
                }
            }
            else
            {
                //usleep(100000); //100ms
                usleep($this->getting_data_wait);
            }
        }

        // Return data
        return $return_data;
    }

    /**
     *
     * Read register
     *
     * @param array $register
     * @param int $ofsset
     * @param int $pdu_address
     * @access private
     * @return string
     *
     */
    private function _readRegister($register, $offset, $pdu_address)
    {
        $command = $this->extention_PDU($this->_command['read'], $offset);

        $offset = $this->check_offset($offset);

        // Variables
        $this->transaction_id++;

        $length = $register['size'];


        // Construct message (STX byte, command etc)
        $message = pack("C2v4",
            $this->_stx,
            $command,
            $pdu_address,
            $this->transaction_id,
            ($register['address'] + $register['size'] * $offset),
            $register['size']);

        // Calculate CRC checksum
        $crc = $this->_calculateCRC($message);

        // Add CRC to message and add ETX byte
        $message .= pack("vC", $crc, $this->_etx);

        // Start with tag
        $tx_msg = $this->_tag;

        // Add message length
        $tx_msg .= pack("n", ($this->_check_bytes_length + strlen($message) + $this->_checksum_length));


        if ($this->debugging == true)
            print "\nReading: $tx_msg\n";


        // Create rc4_msg with check bytes and message
        $rc4_msg = $this->_check_bytes . $message;

        // Add 32-bit checksum to rc4_msg
        $rc4_msg = $rc4_msg . pack("N", $this->_calculateChecksum32bit($rc4_msg));

        // Encrypt rc4_msg and add it to tx_msg
        $tx_msg .= rc4crypt::encrypt($this->_rc4_key, $rc4_msg);


        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging)
            {
                print "Message length: " . strlen($message) . "bytes \n";
            }

            $tx_msg = $message;
        }

        // Check for connection errors
        if (!($this->fp))
        {

            // raiseError($err_str, $err_no);
            if ($this->debugging == true)
                print "\nCannot Read Register: fp is null\n";
            return FALSE;
        }

        // Write command, check for errors
        if (fwrite(($this->fp), $tx_msg) === FALSE)
        {

            // raiseError()
            if ($this->debugging == true)
                print "\nCannot write read message\n";
            return FALSE;
        }

        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging == true)
            {
                print "Wait 300 milieseconds\n";
            }
            usleep(300000); //300000 300 miliseconds
        }

        // Read response

        $tries = 0;
        $done = false;
        $rx_msg = "";
        $rx_array = array();
        $return_data = "";

        while ((!$done) && ($tries < $this->max_retry))
        {
            $rx_msg .= fread(($this->fp), 1024);


            if ($this->debugging == true)
            {
                echo $this->ascii_to_hex($rx_msg);
            }

            $tries++;

            if (strlen($rx_msg) >= 13 + $length)
            {
                if ($this->type_pdu_connection == "GATEWAY")
                {
                    $receivedtag = substr($rx_msg, 0, strlen($this->_tag));

                    // Make sure we have the correct tag
                    if ( $receivedtag== $this->_tag)
                    {
                        // Get message length
                        $message_length = implode(unpack("n", substr($rx_msg, strlen($this->_tag), 2)));

                        // Get RC4 part from rx_msg
                        $rc4_msg = substr($rx_msg, (strlen($this->_tag) + 2), 512);

                        // Decrypt rc4_msg
                        $message = rc4crypt::decrypt($this->_rc4_key, $rc4_msg);

                        // Get checksum from message
                        $message_checksum = implode(unpack("N", substr($message, -$this->_checksum_length, $this->_checksum_length)));

                        // Remove checksum from message
                        $message = substr($message, 0, -$this->_checksum_length);

                        // Generate 32-bit for message (without the checksum)
                        $checksum = $this->_calculateChecksum32bit($message);

                        // Make sure message_checksum and checksum are equal
                        if ($message_checksum == $checksum)
                        {
                            // Get check_bytes from message
                            $message_check_bytes = substr($message, 0, $this->_check_bytes_length);

                            // Remove check_bytes from message
                            $data = substr($message, $this->_check_bytes_length, strlen($message));


                            // Make sure check_bytes match
                            if ($message_check_bytes == $this->_check_bytes)
                            {
                                $data1 = $data;
                                $data = unpack("C*", $data);

                                if(!empty($data) && is_array($data))
                                {
                                    $ACK = $data[1];
                                    $ETX = $data[count($data)];

                                    if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                                    {
                                        $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                                        $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                                        if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                                        {
                                            $command = $data[2];
                                            $pdu_address = $data[3] + $data[4] * 256;
                                            $transaction_id = $data[5] + $data[6] * 256;

                                            $register_start = $data[7] + $data[8] * 256;
                                            $register_length = $data[9] + $data[10] * 256;

                                            // Check of the transaction id is the same as the one that is received
                                            if($this->transaction_id == $transaction_id)
                                            {
                                                // Slice the $rx_array from the 10th position with the length of the $register_length
                                                // The result is an array of data
                                                $result_data = array_slice($data, 10, $length);

                                                // Convert the array to a string of bytes
                                                $return_data = $this->array_to_ascii($result_data);

                                                // transaction id is the same
                                                $done = true;
                                            }
                                        }
                                        else
                                        {
                                            // Not ok
                                            // Raise error -14
                                            if ($this->debugging == true)
                                                print "\nRecieved message is not good\n";
                                        }
                                    }
                                    else
                                    {
                                        if ($this->debugging == true)
                                            print "\nRecieved message is not good\n";
                                    }
                                }
                                else
                                {
                                    // No array
                                    if ($this->debugging == true)
                                        print "\nNo array created from the data\n";
                                }
                            }
                            else
                            {
                                // Raise error -14
                                if ($this->debugging == true)
                                    print "\nInvalid Check Bytes\n";
                            }
                        }
                        else
                        {
                            print "\nInvalid Checksum: Received $message_checksum, expected $checksum\n";
                        }
                    }
                    else
                    {
                        // Raise error -11
                        if ($this->debugging == true)
                            print "\nInvalid Tag: expected $this->_tag but received $receivedtag\n";
                    }
                }
                elseif (($this->type_pdu_connection == "TCP_IP_CONVERTER"))
                {
                    $data = unpack("C*", $rx_msg);

                    if(!empty($data) && is_array($data))
                    {
                        $ACK = $data[1];
                        $ETX = $data[count($data)];

                        if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                        {
                            $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                            {
                                $command = $data[2];
                                $pdu_address = $data[3] + $data[4] * 256;
                                $transaction_id = $data[5] + $data[6] * 256;

                                $register_start = $data[7] + $data[8] * 256;
                                $register_length = $data[9] + $data[10] * 256;

                                // Check of the transaction id is the same as the one that is received
                                if($this->transaction_id == $transaction_id)
                                {
                                    // Slice the $rx_array from the 10th position with the length of the $register_length
                                    // The result is an array of data
                                    $result_data = array_slice($data, 10, $length);

                                    // Convert the array to a string of bytes
                                    $return_data = $this->array_to_ascii($result_data);

                                    // transaction id is the same
                                    $done = true;
                                }
                            }
                            else
                            {
                                // Not ok
                                // Raise error -14
                                if ($this->debugging == true)
                                    print "\nRecieved message is not good\n";
                            }
                        }
                        else
                        {
                            // Not ok
                            // Raise error -14
                            if ($this->debugging == true)
                                print "\nRecieved message is not good\n";
                        }
                    }
                    else
                    {
                        // No array
                        if ($this->debugging == true)
                            print "\nNo array created from the data\n";
                    }
                }
            }
            else
            {
                //usleep(100000); //100ms
                usleep($this->getting_data_wait);
            }
        }


        if(!empty($return_data))
        {

            if ($register['type'] == "int")
            {  // Int register
                if($register['size'] == 1)
                {
                    $return_data = implode(unpack("C", $return_data));
                }
                elseif($register['size'] == 4)
                {
                    $return_data = implode(unpack("V", $return_data));
                }
                else
                {
                    $return_data = implode(unpack("v", $return_data));
                }

            }

            elseif ($register['type'] == "fd")
            {  // Float register
                $r = 0;
                $r = implode(unpack("v",$return_data));

                if ($r > 32767)
                {
                    $return_data = ( $r - 32767)/10;
                }
                else
                {
                    $return_data = $r /100;
                }


            }
            elseif ($register['type'] == 'ascii')
            { // Ascii register
                $return_data = $this->filter_ascii_string($return_data);
            }

            // Return data
            return $return_data;
        }
        else
        {
            return "";
        }
    }

    /**
     *
     * Renumber PDU`s
     *
     * @author mbartels / LaunchIT
     *
     *
     */
    public function Renumber( $start_pdu_address = 1)
    {
        // Start first a scan_bus. You want to know witch PDU`s are connected.
        // Read of every PDU the serial number
        // As last, write the new address. The new address is depended on serialnumber

        if ($this->debugging == true)
            print "\nINFO: Renumber: Start scan bus\n";

        $FoundPDUs = $this->ScanBus();

        if (empty($FoundPDUs) && is_array($FoundPDUs))
        {
            if ($this->debugging == true)
                print "\nERROR: Renumber: No PDU`s found\n";
        }
        else
        {
            $collection_pdu_hardware_address = array();
            foreach ($FoundPDUs as $idx => $unitAddress)
            {
                $collection_pdu_hardware_address[count($collection_pdu_hardware_address)] = $this->getPDUHardwareAddress($unitAddress, true);
            }


            if(!empty($collection_pdu_hardware_address) && is_array($collection_pdu_hardware_address))
            {
                foreach($collection_pdu_hardware_address as $pdu_hardware_address)
                {
                    // Create string for debugging
                    $pdu_hardware_address_string = "";
                    if(!empty($pdu_hardware_address) && is_array($pdu_hardware_address))
                    {
                        foreach($pdu_hardware_address as $hardware_address)
                        {
                            $pdu_hardware_address_string .= $hardware_address;
                        }
                    }


                    if ($this->debugging == true)
                        print "\nINFO: Renumber: Write new pdu address: ".$start_pdu_address." to the PDU with serial number: ".$pdu_hardware_address_string."\n";

                    // write new address
                    $result = $this->RawWriteRenumber($pdu_hardware_address, $start_pdu_address);

                    if($result == false)
                    {
                        // Writing new pdu address has failed
                    }

                    $start_pdu_address++;
                }
            }
            else
            {
                if ($this->debugging == true)
                    print "\nERROR: Renumber: collection PDU serial number is empty\n";
            }
        }
    }



    /**
     *
     * Broadcast write
     *
     * @author mbartels / LaunchIT
     *
     *
     */
    public function writeBroadcast($register, $data, $offset = 1)
    {
        // Pack data
        //$data = $this->_packByRegisterName($register['name'], $data);


        $command = $this->_command['broadcast_write'];

        // Construct message (STX byte, command etc)
//        $message = pack("C2v2",
//                $this->_stx,
//                $command,
//                ($register['address'] + ($register['size'] * $offset)),
//                $register['size']);
        $message = pack("C2v2",
            $this->_stx,
            $command,
            $register['address'],
            $offset);

        // Add truncated data to message
        //$message .= pack("A{$register['size']}", $data);
        $message .= $data;

        // Calculate CRC checksum
        $crc = $this->_calculateCRC($message);

        // Add CRC to message and add ETX byte
        $message .= pack("vC", $crc, $this->_etx);

        // Start with tag
        $tx_msg = $this->_tag;

        // Add message length
        $tx_msg .= pack("n", ($this->_check_bytes_length + strlen($message) + $this->_checksum_length));

        // Create rc4_msg with check bytes and message
        $csm_msg = $this->_check_bytes . $message;

        // Add 32-bit checksum to rc4_msg
        $rc4_msg = $csm_msg . pack("N", $this->_calculateChecksum32bit($csm_msg));

        // Encrypt rc4_msg and add it to tx_msg
        $tx_msg .= rc4crypt::encrypt($this->_rc4_key, $rc4_msg);

        // Open connection
        //$fp = fsockopen($this->_gatewayIPAddress, $this->_gatewayPort, $err_no, $err_str, 5);

        if ($this->type_pdu_connection == "TCP_IP_CONVERTER")
        {
            if ($this->debugging)
            {
                print "Message length: " . strlen($message) . "bytes \n";
            }

            $tx_msg = $message;
        }


        if (!($this->fp))
        {
            if ($this->debugging == true)
                print "\nError in WriteRegister: fp is null\n";
            return FALSE;
        }


        if (fwrite(($this->fp), $tx_msg) === FALSE)
        {
            if ($this->debugging == true)
                print "\nError while writing to output stream\n";
            return FALSE;
        }


//        $rx_msg = fread(($this->fp), 1024);
//        echo $this->ascii_to_hex($rx_msg);

        // No result message expected

        return NULL;
    }


    /*
     * WARNING
     * NOT YET TESTED
     *
     * Firmware upgrade
     */
    public function FWUpgrade($binfile)
    {
        $this->debugging = true;

        $version = "";
        $file_length = 0;
        $cs = "";
        $crc = "";
        $buffer;
        $fld;

        $matches = NULL;
        $pattern = '/SPFW-(\d{4})-(\S{8})-(\S{4}).*.bin/';
        preg_match($pattern, $binfile, $matches); #must match filename like SPFW-0140-004B7929-FE4D_Firmware_RCANDIDATE.bin

        if(!empty($matches))
        {
            $version    = (int)$matches[1];           // from 0130 to 130 (string)
            $checksum   = $matches[2];
            $crc        = $matches[3];


            // Open file
            $fh = fopen($binfile, 'r');

            // Get file length
            $file_size = filesize($binfile);

            // Read file in pices
            // Create array of packets
            $packets = array();
            while (!feof($fh))
            {
                $packets[count($packets)] = fread($fh, 256);
            }

            // Close file
            fclose($fh);

            // Count the amound of packets that has to be send
            $amount_of_packets = (int) ($file_size/256) + 1;

            // convert to hex
            $_crc       = trim(hexdec($crc));
            $_checksum  = trim(hexdec($checksum));


            $msg = pack("vVvvv", $version, $_checksum, $_crc, $amount_of_packets, $file_size);


            $register = $this->getRegisterByName('upvers');
            $number_of_bytes = 12;
            $this->writeBroadcast($register, $msg, $number_of_bytes);

            if ($this->debugging == true)
                print "\nFWU sent header, waiting...\n";


            usleep(7000000);

            foreach ($packets as $i => $value)
            {
                if ($this->debugging == true)
                {
                    if (($i % 50) == 0)
                    {
                        print "FWU sent packet $i of ".count($packets)."\n";
                    }
                }

                $msg = pack("v", $i) . $value;

                $register = $this->getRegisterByName('upblnr');

                $this->writeBroadcast($register, $msg, strlen($msg));


                if($this->type_pdu_connection == "TCP_IP_CONVERTER")
                {
                    usleep(200000);
                }
                else # gateway api can't handle volume at this rate
                {
                    usleep(1000000);
                }

                if ($this->debugging == true)
                {
                    print("\nFWU sent packet: ".$i."\n");
                }
            }

            if ($this->debugging == true)
            {
                print("\nFWU sent packets, waiting...\n");
            }

            usleep(7000000);

            if ($this->debugging == true)
            {
                print("FWU rebooting unit...\n");
            }

            $boot = pack("C", 1);
            $register = $this->getRegisterByName('rsboot');
            $this->writeBroadcast($register, $boot, 1);

            print("FWU reboot done in 15s\n");
            return 1;
        }
        else
        {
            // No mtaches found in title file
            // No version, cs or crc
        }
    }

    /**
     *
     * Pack data based on type by using the register address
     *
     * @param string $address
     * @param string $data
     * @access private
     * @return string
     *
     */
    private function _packByRegisterAddress($address, $data)
    {

        exit("Not yet implemented");
    }

    /**
     *
     * Unpack data based on type by using the register address
     *
     * @param string $address
     * @param string $data
     * @access private
     * @return string
     *
     */
    private function _unpackByRegisterAddress($address, $data)
    {

        exit("Not yet implemented");
    }

    /**
     *
     * Pack data based on type by using the register name
     *
     * @param string $address
     * @param string $data
     * @access private
     * @return string
     *
     */
    private function _packByRegisterName($name, $data)
    {

        // Variables
        $packed = "";

        $register = $this->getRegisterByName($name);
        $type = $register['type'];
        $size = $register['size'];

        if ($type == "int")
        {

            if ($data == 1)
            {
                $packed = pack("C", $data);
            }
            else
            {
                $packed = pack("v", $data);
            }
        }

        if ($type == "fd")
        {

            $packed = pack("v", ($data * 10));
        }

        if ($type == "ascii")
        {

            $packed = pack("a$size", $data);
        }

        return $packed;
    }

    /**
     *
     * Pack data based on data_type
     *
     * @author mbartels / LaunchIT
     *
     * @param string $data_type
     * @param string $data
     * @access private
     * @return string
     *
     */
    private function _packByDataType($data_type, $data, $data_size)
    {
        // Variables
        $packed = "";

        if ($data_type == "int")
        {
            if ($data_size == 1)
            {
                // Single byte
                $packed = pack("C", $data);
            }
            else
            {
                // Short
                $packed = pack("v", $data);
            }
        }

        if ($data_type == "fd")
        {
            $packed = pack("v", ($data * 10));
        }

        if ($data_type == "ascii")
        {
            $packed = pack("a$data_size", $data);
        }

        return $packed;
    }

    /**
     *
     * Pack data based on type by using the register name
     *
     * @param string $address
     * @param string $data
     * @access private
     * @return string
     *
     */
    private function _unpackByRegisterName($name, $data)
    {

        exit("Not yet implemented");
    }

    /**
     *
     * Calculate CRC (CRC16_ccitt_29B1)
     *
     * @param string $data
     * @access private
     * @return string
     *
     */
    private function _calculateCRC($data)
    {
        $count = strlen($data);
        $data = unpack("C*", $data);

        $crc = 0xffff;

        for ($i = 1; $i <= $count; $i++)
        {
            $crc = $crc ^ $data[$i] << 8;

            for ($j = 0; $j < 8; $j++)
            {
                if ($crc & 0x8000)
                {
                    $crc = ($crc << 1) ^ 0x1021;
                }
                else
                {
                    $crc = $crc << 1;
                }
            }
        }

        return $crc & 0xffff;
    }

    /**
     *
     * Calculate 32bit checksum
     *
     * @param string $data
     * @access private
     * @return string
     *
     */
    private function _calculateChecksum32bit($data)
    {

        $sum = 0;

        for ($i = 0; $i < strlen($data); $i++)
        {

            $sum += ord($data[$i]);
        }

        return $sum % 32767;
    }

    // Public functions

    /**
     *
     * Set RC4 key (this needs to be the key configured on the Gateway);
     *
     * @param string $key
     * @access public
     * @return -
     *
     */
    public function setRC4Key($key)
    {

        $this->_rc4_key = $key;

        return TRUE;
    }

    /**
     *
     * Set the IP address of the gateway
     *
     * @param string $ip_address
     * @access public
     * @return -
     *
     */
    public function setGatewayIPAddress($ip_address)
    {

        $this->_gatewayIPAddress = $ip_address;

        return TRUE;
    }

    public function getGatewayIPAddress()
    {
        return $this->_gatewayIPAddress;
    }

    /**
     *
     * Set the TCP port of the gateway
     *
     * @param int $port
     * @access public
     * @return -
     *
     */
    public function setGatewayPort($port)
    {

        $this->_gatewayPort = (int) $port;

        return TRUE;
    }

    /**
     *
     * Wrapper for setGatewayPort()
     *
     * @param int $port
     * @access public
     * @return -
     *
     */
    public function setGatewayTCPPort($port)
    {

        $this->setGatewayPort($port);

        return TRUE;
    }

    /**
     *
     * Get register by name
     *
     * @param string $name
     * @access public
     * @return array
     *
     */
    public function getRegisterByName($name)
    {

        if (!array_key_exists($name, $this->_datamodel))
        {

            // raiseError
            if ($this->debugging == true)
                print "\nRegister not found\n";
            return FALSE;
        }

        return $this->_datamodel[$name];
    }

    /**
     *
     * Unlock PDU outlet
     *
     * @param int $pdu_address
     * @param int $pdu_channel
     * @param string $name
     * @access public
     * @return -
     *
     */
    public function setPDUOutletUnlock($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("swounl");


        return $this->writeRegister($register, $pdu_channel, $pdu_address, 1);
    }

    /**
     *
     * Unlock PDU outlet
     *
     * @param int $pdu_address
     * @param int $pdu_channel
     * @param string $name
     * @access public
     * @return -
     *
     */
    public function setPDUOutletName($pdu_address, $outlet_name, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("stolnm");


        return $this->writeRegister($register, $pdu_channel, $pdu_address, $outlet_name);
    }

    /**
     *
     * Get PDU outlet unlock
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletUnlock($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("swounl");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        $value = str_replace("\0", " ", $value);

        return $value;
    }

    /**
     *
     * Set PDU outlet state to OFF
     *
     * @param int $pdu_address
     * @param int $pdu_channel
     * @param string $name
     * @access public
     * @return -
     *
     */
    public function setPDUOutletStateOff($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("swocst");

        return $this->writeRegister($register, $pdu_channel, $pdu_address, 0);
    }

    /**
     *
     * Set PDU outlet state to ON
     *
     * @param int $pdu_address
     * @param int $pdu_channel
     * @param string $name
     * @access public
     * @return -
     *
     */
    public function setPDUOutletStateOn($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("swocst");

        return $this->writeRegister($register, $pdu_channel, $pdu_address, 1);
    }


    /**
     *
     * Set PDU outlet state to ON
     *
     * @param int $pdu_address
     * @param int $pdu_channel
     * @param string $name
     * @access public
     * @return -
     *
     */
    public function resetPDUkWhOutletSubtotal($pdu_address, $pdu_channel = 0)
    {
        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("rsomks");

        return $this->writeRegister($register, $pdu_channel, $pdu_address, 1);
    }

    /**
     *
     * Set PDU outlet state to ON
     *
     * @param int $pdu_address
     * @param int $pdu_channel
     * @param string $name
     * @access public
     * @return -
     *
     */


    public function resetPDUkWhInletSubtotal($pdu_address, $pdu_channel = 0)
    {
        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("rsimks");

        return $this->writeRegister($register, $pdu_channel, $pdu_address, 1);
    }

    /**
     *
     * Get PDU outlet name
     *
     * @param int $pdu_address
     * @param int $pdu_channel
     * @param string $name
     * @access public
     * @return -
     *
     */


    /**
     *
     * Get PDU data model version
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUDatamodelVersion($pdu_address)
    {

        $register = $this->getRegisterByName("idspdm");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU firmware revision number
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUFirmwareVersion($pdu_address)
    {

        $register = $this->getRegisterByName("idfwvs");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU sales order number
     *
     * @param int $pdu_address
     * @access public
     * @return string
     *
     */
    public function getPDUSalesOrderNumber($pdu_address)
    {

        $register = $this->getRegisterByName("idonbr");

        $value = $this->_readRegister($register, 0, $pdu_address);

        $value = str_replace("\0", " ", $value);

        return $value;
    }

    /**
     *
     * Get PDU product id
     *
     * @param int $pdu_address
     * @access public
     * @return string
     *
     */
    public function getPDUProductId($pdu_address)
    {

        $register = $this->getRegisterByName("idpart");

        $value = $this->_readRegister($register, 0, $pdu_address);

        $value = str_replace("\0", " ", $value);

        return $value;
    }

    /**
     *
     * Get PDU serial number
     *
     * @param int $pdu_address
     * @access public
     * @return string
     *
     */
    public function getPDUSerialNumber($pdu_address)
    {

        $register = $this->getRegisterByName("idsnbr");

        $value = $this->_readRegister($register, 0, $pdu_address);

        $value = str_replace("\0", " ", $value);

        return $value;
    }

    /**
     *
     * Get PDU hardware address
     *
     * @param int $pdu_address
     * @access public
     * @return string
     *
     */
    public function getPDUHardwareAddress($pdu_address, $return_as_integer = FALSE)
    {
        $register = $this->getRegisterByName("idchip");
        $value = NULL;

        /*
         * TODO REVIEW THIS PART OF THE FUNCTION | mbartels
         */
        if($return_as_integer === TRUE)
        {
            $settings_bytes = $register['channels'] * $register['size'];

            $datablock = $this->ReadRaw($register['address'], $settings_bytes, $pdu_address);

            // Unpack the register block to a byte array
            $register_block_byte_array = unpack("C*", $datablock);

            if (count($register_block_byte_array) <= 0)
            {
                System_Daemon::log(System_Daemon::LOG_INFO, "WARNING: Register_block does not contain any item! $pdu_address");
                return null;
            }
            if (count($register_block_byte_array) == 1)
            {
                // This is an error code instead of a register block
                $error_code = $register_block_byte_array[1] - 256;
                System_Daemon::log(System_Daemon::LOG_INFO, "WARNING: Obtained errorcode $error_code while parsing registers of $pdu_address and register ".$register['address']);
                return null;
            }


            // We are expecting the amount of bytes set in the datamodel. An Integer can actually disguise as a char (1 byte), a short (2 bytes) or a 3 byte integer
            $missingdatacounter = 0;
            $counter = 0;
            $return_values = array();

            $channels = $register['channels'];

            for($ch = 0; $channels > $ch; $ch++)
            {
                // Init the result to 0
                $result_register = 0;

                $nbytes = $register['size'];

                for ($idxbyte = 0; ($idxbyte < $nbytes); $idxbyte++)
                {
                    if (isset($register_block_byte_array[$counter + 1]))
                    {
                        $byteval = $register_block_byte_array[$counter + 1];
                        $multiplier = pow(256, ($idxbyte));
                        $result_register += ( $byteval * $multiplier);
                    }

                    else
                    {
                        // Somehow the byte we expected was not found in the obtained block
                        $missingdatacounter++;
                        //$amount_of_errors++;
                    }

                    $counter++;
                }
                $return_values[count($return_values)] = $result_register;
            }

            if($missingdatacounter > 0)
            {
                $value = FALSE;
            }
            else
            {
                $value = $return_values;
            }
        }
        else
        {
            $value_1 = $this->_readRegister($register, 0, $pdu_address);
            $value_2 = $this->_readRegister($register, 1, $pdu_address);
            $value_3 = $this->_readRegister($register, 2, $pdu_address);

            //var_dump($value_1,$value_2, $value_3);


            //if(($value_1 != FALSE && $value_1 != "") && ($value_2 != FALSE && $value_2 != "") && ($value_3 != FALSE && $value_3 != ""))
            {
                $value = $value_1 . "-".$value_2 . "-".$value_3;
                //var_dump($value);

            }
            //else
            //{
            //    $value = FALSE;
            //}


        }


        return $value;
    }

    /**
     *
     * Get PDU phase total
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUUnitAddress($pdu_address)
    {

        $register = $this->getRegisterByName("idaddr");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }
    public function getPDUPhaseTotal($pdu_address)
    {

        $register = $this->getRegisterByName("cfnrph");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU outlet total
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletTotal($pdu_address)
    {

        $register = $this->getRegisterByName("cfnrno");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU switched outlet total
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUSwitchedOutletTotal($pdu_address)
    {

        $register = $this->getRegisterByName("cfnrso");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU measured outlet total
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUMeasuredOutletTotal($pdu_address)
    {

        $register = $this->getRegisterByName("cfnrmo");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU maximum load
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUMaximumLoad($pdu_address)
    {

        $register = $this->getRegisterByName("cfamps");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU temperature sensor total
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUTemperatureSensorTotal($pdu_address)
    {

        $register = $this->getRegisterByName("cfnrte");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU device status code
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUDeviceStatusCode($pdu_address)
    {

        $register = $this->getRegisterByName("ssstat");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU temperature alert
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUTemperatureAlert($pdu_address)
    {

        $register = $this->getRegisterByName("ssttri");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU input current alert
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUInputCurrentAlert($pdu_address)
    {

        $register = $this->getRegisterByName("ssitri");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU output current alert
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutputCurrentAlert($pdu_address)
    {

        $register = $this->getRegisterByName("ssotri");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU input voltage alert
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUInputVoltageAlert($pdu_address)
    {

        $register = $this->getRegisterByName("ssvtri");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU fuse blown alert
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUFuseBlownAlert($pdu_address)
    {

        $register = $this->getRegisterByName("ssftri");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }
    /* Get blown fuse alert


    */

    public function getPDUiCurrentAlert($pdu_address)
    {

        $register = $this->getRegisterByName("ssicda");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }
    public function getPDUoCurrentAlert($pdu_address)
    {

        $register = $this->getRegisterByName("ssftri");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU device name
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUDeviceName($pdu_address)
    {

        $register = $this->getRegisterByName("stdvnm");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU device location
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUDeviceLocation($pdu_address)
    {

        $register = $this->getRegisterByName("stdvlc");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU vanity tag
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUVanityTag($pdu_address)
    {

        $register = $this->getRegisterByName("stuser");

        $value = $this->_readRegister($register, 0, $pdu_address);

        $value = str_replace("\0", " ", $value);

        return $value;
    }

    /**
     *
     * Get PDU peak duration
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUPeakDuration($pdu_address)
    {

        $register = $this->getRegisterByName("stpkdr");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;

    }

    /**
     *
     * Get PDU dip duration
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUDipDuration($pdu_address)
    {

        $register = $this->getRegisterByName("stdpdr");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU fixed outlet delay
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUFixedOutletDelay($pdu_address)
    {

        $register = $this->getRegisterByName("stfodl");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU fixed outlet delay
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUPowerSaverMode($pdu_address)
    {

        $register = $this->getRegisterByName("stpsav");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU outlet powerup mode
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletPowerupMode($pdu_address)
    {

        $register = $this->getRegisterByName("stopom");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU maximum temperature
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUMaximumTemperature($pdu_address)
    {

        $register = $this->getRegisterByName("stmaxt");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU display orientation
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUDisplayOrientation($pdu_address)
    {

        $register = $this->getRegisterByName("stdiso");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU maximum inlet amps
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUMaximumInletAmps($pdu_address)
    {

        $register = $this->getRegisterByName("stimcm");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }


    /**
     *
     * Get PDU maximum outlet amps
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletMaximumAmps($pdu_address)
    {

        $register = $this->getRegisterByName("stomcm");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }


    /**
     *
     * Get PDU outlet delay
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletDelay($pdu_address)
    {

        $register = $this->getRegisterByName("stiodl");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }
    /*
    public function getPDUOutletDelay($pdu_address, $pdu_channel)
    {

        if ($pdu_channel < 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("stiodl");

        $value = $this->_readRegister($register, $pdu_channel, 1);

        return $value;
    }*/

    /**
     *
     * Get PDU outlet state
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletState($pdu_address, $pdu_channel)
    {

        if ($pdu_channel < 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("swocst");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU outlet scheduled activity
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletScheduledActivity($pdu_address, $pdu_channel)
    {

        if ($pdu_channel < 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("swosch");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU kWh total
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUkWhTotal($pdu_address, $phase = 0)
    {

        if ($phase <= 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;
        }

        $register = $this->getRegisterByName("imkwht");

        $value = $this->_readRegister($register, $phase, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU kWh subtotal
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUkWhSubtotal($pdu_address, $phase = 0)
    {

        if ($phase < 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;
        }

        $register = $this->getRegisterByName("imkwhs");

        $value = $this->_readRegister($register, $phase, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU power factor
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUPowerFactor($pdu_address, $phase = 0)
    {

        if ($phase <= 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;
        }

        $register = $this->getRegisterByName("impfac");

        $value = $this->_readRegister($register, $phase, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU actual current
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUActualCurrent($pdu_address, $phase = 0)
    {

        if ($phase <= 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;
        }

        $register = $this->getRegisterByName("imcrac");

        $value = $this->_readRegister($register, $phase, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU peak current
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUPeakCurrent($pdu_address, $phase = 0)
    {

        if ($phase <= 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;
        }

        $register = $this->getRegisterByName("imcrpk");

        $value = $this->_readRegister($register, $phase, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU actual voltage
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUActualVoltage($pdu_address, $phase = 0)
    {

        if ($phase <= 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;
        }

        $register = $this->getRegisterByName("imvoac");

        $value = $this->_readRegister($register, $phase, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU lowest voltage
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDULowestVoltage($pdu_address, $phase = 0)
    {

        if ($phase <= 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;
        }

        $register = $this->getRegisterByName("imvodp");

        $value = $this->_readRegister($register, $phase, $pdu_address);

        return $value;
    }
    public function getPDUWhSubtotalfraction($pdu_address, $phase = 0)
    {

        if ($phase <= 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;
        }

        $register = $this->getRegisterByName("imwkhf");

        $value = $this->_readRegister($register, $phase, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU outlet kWh total
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletkWhTotal($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("omkwht");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }
    public function getPDUSensorValue($pdu_address, $pdu_channel)
    {

        if ($pdu_channel < 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("snsval");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }
    public function getPDUSensorType($pdu_address, $pdu_channel)
    {

        if ($pdu_channel < 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("snstyp");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }
    public function getPDUOutputCTratio($pdu_address, $pdu_channel)
    {

        if ($pdu_channel < 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("stomct");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }
    public function getPDUInputCTratio($pdu_address, $pdu_channel)
    {

        if ($pdu_channel < 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("stimct");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }
    public function getPDUOutletName($pdu_address, $pdu_channel)
    {

        if ($pdu_channel < 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("stolnm");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }



    /**
     *
     * Get PDU outlet kWh subtotal
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletkWhSubtotal($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("omkwhs");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU outlet power factor
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletPowerFactor($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("ompfac");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU outlet actual current
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletActualCurrent($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("omcrac");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU outlet peak current
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletPeakCurrent($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("omcrpk");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU outlet actual voltage
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletActualVoltage($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("omvoac");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }
    public function getPDUOutletsuWhSubtotal($pdu_address, $pdu_channel = 0)
    {

        if ($pdu_channel <= 0)
        {
            $pdu_channel = 0;
        }
        else
        {
            $pdu_channel--;
        }

        $register = $this->getRegisterByName("omuwhs");

        $value = $this->_readRegister($register, $pdu_channel, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU internal temperature
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUInternalTemperature($pdu_address)
    {

        $register = $this->getRegisterByName("pditem");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU external temperature
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUExternalTemperature($pdu_address)
    {

        $register = $this->getRegisterByName("pdetem");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }
    public function getPDUdataBlockNumber($pdu_address)
    {

        $register = $this->getRegisterByName("upblnr");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }
    public function getPDUdataBlock($pdu_address)
    {

        $register = $this->getRegisterByName("updata");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }



    /**
     *
     * Get PDU internal peak temperature
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUInternalPeakTemperature($pdu_address)
    {

        $register = $this->getRegisterByName("pdinpk");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU external peak temperature
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUExternalPeakTemperature($pdu_address)
    {

        $register = $this->getRegisterByName("pdexpk");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    /**
     *
     * Get PDU switched outlet total
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUInletTotal($pdu_address)
    {

        $register = $this->getRegisterByName("cfnrph");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }


    /**
     * Set the type of PDU connection.
     * These options are available: GATEWAY | SERIAL_PORT | TCP_IP_CONVERTER
     *
     * @param string $type_pdu_connection
     */
    public function setTypePDUConnection($type_pdu_connection = "GATEWAY")
    {
        $this->type_pdu_connection = $type_pdu_connection;

        return TRUE;
    }

    /**
     *
     * Get PDU environment sensors
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUSensorName($pdu_address)
    {

        $register = $this->getRegisterByName("snsnme");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    public function getPDUversion($pdu_address)
    {

        $register = $this->getRegisterByName("upvers");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }
    public function getFirmwareIsValid($pdu_address)
    {

        $register = $this->getRegisterByName("upckok");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }

    public function getPDUNumberOfEnvSensors($pdu_address)
    {

        $register = $this->getRegisterByName("cfnres");

        $value = $this->_readRegister($register, 0, $pdu_address);

        return $value;
    }


    /**
     * Trim value after finding a null character
     *
     * @author mbartels | Ben Vaessen / LaunchIT
     * @param ascii $value
     */
    private function filter_ascii_string($value)
    {
        $found = false;
        for ($count = 0; $count < strlen($value); $count++)
        {
            if ($value[$count] == "\0")
            {
                $found = true;
            }
            elseif (ord($value[$count]) < 32 || ord($value[$count]) > 126)
            {
                $value[$count] = "_";
            }

            if ($found === true)
            {
                $value[$count] = " ";
            }
        }

        return $value;
    }

    public function ascii_to_hex($ascii)
    {
        $hex = '';
        for ($i = 0; $i < strlen($ascii); $i++)
        {
            $byte = strtoupper(dechex(ord($ascii{$i})));
            $byte = str_repeat('0', 2 - strlen($byte)) . $byte;
            $hex .= $byte . " ";
        }
        return $hex;
    }

    private function ascii_to_array($ascii)
    {
        $rx_array = array();

        for ($i = 0; $i < strlen($ascii); $i++)
        {
            $byte = strtoupper(ord($ascii{$i}));
            //$byte = str_repeat('0', 2 - strlen($byte)) . $byte;

            // Check if the length is bigger than 0
            if(2 - strlen($byte) > 0)
            {
                $byte = str_repeat('', 2 - strlen($byte)) . $byte;
            }

            $rx_array[count($rx_array)] = $byte;
        }

        return $rx_array;
    }

    private function array_to_ascii($array)
    {
        $ascii = '';

        for ($i = 0; $i < count($array); $i++)
        {
            //var_dump($array[$i], hexdec(($array[$i])), chr(hexdec(($array[$i]))));
            $ascii.= chr(($array[$i]));
        }

        return $ascii;
    }


    /**
     *
     * @param type $channel
     * @param type $command
     * @return register
     */
    private function extention_PDU($command, $channel)
    {
        $retval = $command;

        if(isset($command) && isset($channel))
        {
            if($channel >= 27)
            {
                // Channel is bigger than 27
                $retval = $command + 1;
            }
            else
            {
                // Channel is smaller or equal 27
                $retval = $command;
            }
        }

        return $retval;
    }


    private function check_offset($offset)
    {
        $retval = $offset;

        if(isset($offset))
        {
            if($offset >= 27)
            {
                // Channel is bigger than 27
                $retval = $offset - 27;
            }
        }

        return $retval;
    }

    private function print_error($data)
    {
        try
        {
            $error_code = $data - 265;

            if($error_code < 0)
            {
                $source =   $this->_errors[$error_code]['source'];
                $message =  $this->_errors[$error_code]['message'];

                print "Error code: ".$error_code.", Source: ".$source.", Message: ".$message;
            }
            else
            {
                // No good value
                // value must be lower than 0
            }
        }
        catch (Exception $ex)
        {
            print "Exception: ".$ex->getMessage().", Data: ".$data;
        }

    }
}

?>

