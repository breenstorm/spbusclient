<?php

/**********************************************************************

PHP SPBus API for Schleifenbauer PDUs

Schleifenbauer Engineering B.V.
All rights reserved, no warranties
Last update: 2016-07-06, by L. Boer

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
    private $logging = true;
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

    private $max_retry = 10;

    private $transaction_id = 0;
    private $time_out_connection = 3; // seconds

    private $scantimeoutoverall = 5; // seconds, the time that is needed for grabbing a gateway packet
    private $getting_data_wait = 10000; // 10 milliseconds
    private $socket_timeout_s = 3; # Sec [1]
    private $socket_timeout_us = 0; //10000; # uSec [10000]
    private $yield = 100000; # uSec [10000] 0 for fastest, single API access, 10000000 or higher to play nice with other APIs like DCS
    private $waitForAnswer = 28000; # uSec [28000]

    private $logfile;

    /*
     * Initialisation of the error catching
     */
    public function noticeError($errno, $errstr)
    {
        if($errno != 2) //Error 2 is excluded as it happens regularly on retries.
        {
            $this->log_print("Error: [$errno] $errstr");
        }
    }
    /*
     * Constructor
     */
    public function __construct()
    {

        // Load standard variables with their values
        $this->init();

        // Load datamodel
        $this->_loadDataModel();

        // Load errors
        $this->_loadErrors();

        // Activate error handler
        set_error_handler(array($this, 'noticeError'), E_ALL);

        // Name of the logfile starts with LogfileSPbus_ because it only logs the messages of the SPbus class.
        // Name further contains the date of the logging
        $this->logfile = 	'LogfileSPbus_'.
            date("Y-m-d",time()).
            '.log';
    }

    // Function to send all logging data to a file instead of the regular output
    private function log_print($string)
    {
        if($this->logging == true)
        {
            // Trace which function is calling the logging
            $trace = debug_backtrace();

            // Build the message to be send with timestamp and trace
            $sendmessage = "\n".date("Y-m-d H:i:s.ms",time())."\t";
            if(!empty($trace[3]))
            {
                $sendmessage .= $trace[3]['function']."-> ";
            }

            if(!empty($trace[2]))
            {
                $sendmessage .= $trace[2]['function']."-> ";
            }
            $sendmessage .= $trace[1]['function']."\t||\t".$string;

            // Write the message
            file_put_contents(	$this->logfile,
                $sendmessage,
                FILE_APPEND | LOCK_EX);
        }
    }
    /*
     * Function to write a message to the hPDU and receive its reaction
     */
    public function sp_rw_transaction($msg)
    {
        $tries = 0;
        $done = FALSE;
        $result = FALSE;

        while ((!$done) && ($tries < $this->max_retry))
        {
            #(increasing) delay after the first attempt
            usleep($tries * 0.1 * 1e6);

            $this->Connect();

            if ($this->fp){

                $write = fwrite($this->fp, $msg);
                if ($write === FALSE)
                {
                    if ($this->debugging == true)
                        $this->log_print(  "Cannot write transaction message");
                }
                else
                {
                    usleep($this->waitForAnswer);

                    $result = fread($this->fp, 512);
                    if ($result){
                        $done = true;
                    } else				{
                        if ($this->debugging == true)
                            $this->log_print(  "Cannot read transaction message");
                    }
                }
                $this->Disconnect();
            }
            #increasing delay before retrying
            $tries++;
        }

        if($tries >= $this->max_retry){
            $this->log_print(  "Transaction failed after " . $tries . " tries");
        }

        return $result;
    }

    /*
     * Write a message without retry or reading a reaction
     */
    public function ffwrite($msg)
    {
        $this->Connect();

        if ($this->fp){
            $write = fwrite(($this->fp), $msg);
            usleep($this->waitForAnswer);
            return $write;
        }
        else
            return false;
    }

    /*
     *  Simple read function
     */
    public function ffread($len)
    {
        $r = fread(($this->fp), $len);
        return $r;
    }
    /*
     * Packing the messages that need to be transmitted, and adding rc4 and checksum
     * These steps are used for every transmit message
     */
    private function _packTX_MSG($message)
    {
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

        return $tx_msg;
    }
    /*
     * Unpacking the returned message, while checking correctness
     * These steps are used for every received message
     */
    private function _unpackRX_MSG($rx_msg)
    {
        if(!empty($rx_msg))
        {
            if ($this->debugging == true)
            {
                var_dump($this->ascii_to_hex($rx_msg));
            }

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
                            return $data;
                        }
                        else
                        {
                            // No array
                            if ($this->debugging == true)
                                $this->log_print(  "No array created from the data");
                        }
                    }
                    else
                    {
                        // Raise error -14
                        $this->log_print(  "Invalid Check Bytes");
                    }
                }
                else
                {
                    $this->log_print(  "Invalid Checksum: Received $message_checksum, expected $checksum");
                }
            }
            else
            {
                // Raise error -11
                $this->log_print(  "Invalid Tag: expected $this->_tag but received $receivedtag");
            }
        }
        return FALSE;
    }

    /*
     *
     */
    private function _unpackRX_DATA($data)
    {
        $ACK = $data[1];
        $ETX = $data[count($data)];

        if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
        {
            $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
            {
                return true;
            }
            else if($this->debugging == true)
            {
                if(!($ACK == $this->_ack))
                    $this->log_print("ACK error in received packets");

                if(!($ETX == $this->_etx))
                    $this->log_print("ETX error in received packets");

                if(!($CRC == $calc_crc_received))
                    $this->log_print("CRC error in received packets");
            }
        }
        else
        {
            if ($this->debugging == true)
            {
                $this->$this->log_print( _error($data[1]));
            }
        }
        return false;
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
        if (is_resource($this->fp))
        {
            if ($this->debugging == true)
                $this->log_print( ( "Closing Connection"));
            fclose($this->fp);
        }

        $this->fp = false;
    }


    public function Connect()
    {
        #give some time to concurrent interfaces to connect
        usleep($this->yield);

        if (!isset($this->_gatewayPort))
        {
            if ($this->debugging == true)
                $this->log_print( ( "Error: Port is not set"));
            return false;
        }

        if ($this->_gatewayPort <= 0)
        {
            if ($this->debugging == true)
                $this->log_print( ( "Error: Port is Invalid"));
            return false;
        }

        if (!isset($this->_gatewayIPAddress))
        {
            if ($this->debugging == true)
                $this->log_print( ( "Error: Gateway IP Address is not set"));
            return false;
        }

        if (strlen($this->_gatewayIPAddress) < 8)
        {
            if ($this->debugging == true)
                $this->log_print( ( "Error: gateway Address cannot be shorter than 8 characters"));
            return false;
        }

        try
        {
            // Close any open connections
            if ($this->fp)
            {
                if ($this->debugging == true)
                    $this->log_print( ( "Closing Connection"));
                fclose($this->fp);
            }

            // Open connection
            $this->fp = @fsockopen($this->_gatewayIPAddress, $this->_gatewayPort, $err_no, $err_str, $this->time_out_connection);

            if($this->fp != FALSE)
            {
                stream_set_timeout($this->fp, $this->socket_timeout_s, $this->socket_timeout_us);
            }

            if ($this->debugging == true)
                $this->log_print( ( "Socket opened for Gateway ".$this->_gatewayIPAddress.""));

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
        $this->_rc4_key = "0000000000000000";

        // Define check bytes based on RC4 key
        $this->_check_bytes_length = 4;
        $this->_check_bytes = substr($this->_rc4_key, 0, $this->_check_bytes_length);

        // Define checksum length
        $this->_checksum_length = 4;

        // Gateway
        $this->_gatewayIPAddress = 0;
        $this->_gatewayPort = 0;

        //      $this->type_pdu_connection = "GATEWAY";
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
                $this->log_print( ( "File $errors_file does not exist"));
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
            switch($group)
            {
                case 'identification':
                    $this->_datamodel[$name]['register'] = 100;
                    $this->_datamodel[$name]['register_length'] = 79;
                    break;
                case 'configuration':
                    $this->_datamodel[$name]['register'] = 200;
                    $this->_datamodel[$name]['register_length'] = 10;
                    break;
                case 'system_status':
                    $this->_datamodel[$name]['register'] = 300;
                    $this->_datamodel[$name]['register_length'] = 9;
                    break;
                case 'reset':
                    $this->_datamodel[$name]['register'] = 400;
                    $this->_datamodel[$name]['register_length'] = 31;
                    break;
                case 'settings':
                    $this->_datamodel[$name]['register'] = 1000;
                    $this->_datamodel[$name]['register_length'] = 447;
                    break;
                case 'switched_outlets':
                    $this->_datamodel[$name]['register'] = 2000;
                    $this->_datamodel[$name]['register_length'] = 108;
                    break;
                case 'input_measures':
                    $this->_datamodel[$name]['register'] = 3000;
                    $this->_datamodel[$name]['register_length'] = 60;
                    break;
                case 'output_measures':
                    $this->_datamodel[$name]['register'] = 4000;
                    $this->_datamodel[$name]['register_length'] = 382;
                    break;
                case 'pdu_measures':
                    $this->_datamodel[$name]['register'] = 5000;
                    $this->_datamodel[$name]['register_length'] = 152;
                    break;
                case 'virtual':
                    $this->_datamodel[$name]['register'] = 9000;
                    $this->_datamodel[$name]['register_length'] = 204;
                    break;
                case 'upload info':
                    $this->_datamodel[$name]['register'] = 10000;
                    $this->_datamodel[$name]['register_length'] = 13;
                    break;
                case 'upload data':
                    $this->_datamodel[$name]['register'] = 10100;
                    $this->_datamodel[$name]['register_length'] = 258;
                    break;
                case 'calibration':
                    $this->_datamodel[$name]['register'] = 20000;
                    $this->_datamodel[$name]['register_length'] = 30;
                    break;
                case 'host':
                    $this->_datamodel[$name]['register'] = 40000;
                    $this->_datamodel[$name]['register_length'] = 2578;
                    break;
            }
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

        // Pack the transmit message, including rc4 and checksum
        $tx_msg = $this->_packTX_MSG($message);

        $done = False;
        $rx_msg = "";
        // $rx_array = array();

        $rx_msg = $this->sp_rw_transaction($tx_msg);

        $data = $this->_unpackRX_MSG($rx_msg);
        if($data != FALSE)
        {
            /* 			$ACK = $data[1];
                        $ETX = $data[count($data)];

                        if(isset($data[count($data) - 2]) && isset($data[count($data) - 1]))
                        {
                            $CRC = $data[count($data) - 2] +  $data[count($data) - 1] * 256;

                            $calc_crc_received = $this->_calculateCRC($this->array_to_ascii(array_slice($data, 0, count($data) - 3)));

                            if($ACK == $this->_ack && $ETX == $this->_etx && $CRC == $calc_crc_received)
                            {
                                $command = $data[2]; */
            if($this->_unpackRX_DATA($data))
            {
                $pdu_address = $data[3] + $data[4] * 256;
                $transaction_id = $data[5] + $data[6] * 256;

                // Check of the transaction id is the same as the one that is received
                if($this->transaction_id == $transaction_id)
                {
                    // transaction id is the same
                    $done = true;
                }
            }
            /* 	else
                {
                    // Not ok
                    // Raise error -14
                    if ($this->debugging == true)
                        $this->log_print( ( "Message receive error"));
                }
            }
            else
            {
                // Not ok
                // Raise error -14
                if ($this->debugging == true)
                    $this->log_print( ( "Message receive error"));
            }  */
        }
        else
        {
            usleep($this->getting_data_wait);
        }
        return $done;
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
        // Variables
        $this->transaction_id++;
        $done = False;
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
                    $this->log_print( ( "Error data is not packed"));
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

            // Pack the transmit message, including rc4 and checksum
            $tx_msg = $this->_packTX_MSG($message);

            if ($rx_msg = $this->sp_rw_transaction($tx_msg) === FALSE)
            {
                if ($this->debugging == true)
                    $this->log_print( ( "Error while writing to output stream"));
                return FALSE;
            }

            // Read response

            $data = $this->_unpackRX_MSG($rx_msg);
            if($data != FALSE)
            {
                if($this->_unpackRX_DATA($data))
                {
                    $transaction_id = $data[5] + $data[6] * 256;

                    // Check of the transaction id is the same as the one that is received
                    if($this->transaction_id == $transaction_id)
                    {
                        // transaction id is the same
                        $done = true;
                    }
                }
            }
        }
        return $done;
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
        $done = FALSE;
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

            // Pack the transmit message, including rc4 and checksum
            $tx_msg = $this->_packTX_MSG($message);

            if ($this->ffwrite($tx_msg) === FALSE || $tx_msg === FALSE)
            {
                if ($this->debugging == true)
                    $this->log_print( ( "Error while writing to output stream"));
                return FALSE;
            }
            $_hardware_address = implode("", $this->getPDUHardwareAddress($new_pdu_address, true));

            if($_hardware_address == $hardware_address_string)
            {
                $done = true;
            }
            else
            {
                // Not ok
                if ($this->debugging == true)
                {
                    $this->log_print( ( "Message is from other PDU. Hardware address is not the same"));
                }
            }
        }
        return $done;
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
            $this->log_print(  "Started Alert Scan");

        // Construct message (STX byte, command etc)
        $message = pack("C2", $this->_stx, $this->_command['alert_scan']);

        // Pack the transmit message, including rc4 and checksum
        $tx_msg = $this->_packTX_MSG($message);

        // Write command, check for errors
        if ($this->ffwrite($tx_msg) === FALSE)
        {
            if ($this->debugging == true)
                $this->log_print(  "Error while writing scan message");
            return FALSE;
        }

        $time_start = microtime(true);
        $time_now = microtime(true);
        $time = $time_now - $time_start;

        $found_ids = array();
        $n_found = 0;

        stream_set_timeout(($this->fp), 10);


        while ($time < $this->scantimeoutoverall)
        {
            // Read response
            $rx_msg = $this->ffread(1024);

            $data = $this->_unpackRX_MSG($rx_msg);
            if($data != FALSE)
            {
                $time_start = microtime(true);
                // The $data is one big array where all the messages data will be stored.
                // One PDU scan message is 13 bytes long.
                // Split array in pices of 13 bytes
                $result_array = array_chunk($data, 13, TRUE);

                foreach ($result_array as $rx_array)
                {
                    if($this->_unpackRX_DATA($rx_array))
                    {
                        $status = $rx_array[5];

                        if ($status != 0)
                        {
                            $found_ids[$n_found] = $rx_array[3] + $rx_array[4] * 256;
                            $n_found++;
                        }
                    }
                }
            }
            $time_now = microtime(true);
            $time = $time_now - $time_start;

        }

        if ($this->debugging == true)
        {
            $this->log_print(  "Found id`s: ");
            foreach ($found_ids as $key => $ids)
            {
                $this->log_print(  " - " . $ids . "");
            }
        }

        // Return found IDs
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
            $this->log_print(  "Started Scan");

        // Construct message (STX byte, command etc)
        $message = pack("C2", $this->_stx, $this->_command['scan']);

        // Pack the transmit message, including rc4 and checksum
        $tx_msg = $this->_packTX_MSG($message);

        // Write command, check for errors
        if ($this->ffwrite($tx_msg) === FALSE)
        {
            // raiseError()
            if ($this->debugging == true)
                $this->log_print(  "Error while writing scan message");
            return FALSE;
        }

        $time_start = microtime(true);
        $time_now = microtime(true);
        $time = $time_now - $time_start;

        $found_ids = array();
        $n_found = 0;

        stream_set_timeout(($this->fp), 10); // timeout to 10 seconds because the scan may take a while

        while ($time < $this->scantimeoutoverall)
        {
            // Read response
            $rx_msg = $this->ffread(27);

            $data = $this->_unpackRX_MSG($rx_msg);
            if($data != FALSE)
            {
                // The $data is one big array where all the messages data will be stored.
                // One PDU scan message is 13 bytes long.
                // Split array in pieces of 13 bytes
                $result_array = array_chunk($data, 13, TRUE);

                foreach ($result_array as $rx_array)
                {
                    if ($this->_unpackRX_DATA($rx_array) == true)
                    {
                        $found_ids[$n_found] = $rx_array[3] + $rx_array[4] * 256;
                        $n_found++;
                    }
                }
            }
            $time_now = microtime(true);
            $time = $time_now - $time_start;
        }

        if ($this->debugging == true)
        {
            $this->log_print(  "Found id`s: ");

            foreach ($found_ids as $key => $ids)
            {
                $this->log_print(  " - " . $ids . "");
            }
        }

        // Return found IDs
        return $found_ids;
    }

    /**
     *
     * Read raw register
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
            $this->log_print(  "Reading $length bytes starting at register $start, on PDU $pdu_address");

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

        // Pack the transmit message, including rc4 and checksum
        $tx_msg = $this->_packTX_MSG($message);

        $return_data = array();

        $rx_msg = $this->sp_rw_transaction($tx_msg);

        $data = $this->_unpackRX_MSG($rx_msg);
        if($data !=FALSE)
        {
            if($this->_unpackRX_DATA($data))
            {
                $transaction_id = $data[5] + $data[6] * 256;

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
        }
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
        //     $command = $this->extention_PDU($this->_command['read'], $offset);

        $offset = $this->check_offset($offset);

        $length = $register['size'];

        $return_data = $this->ReadRaw(($register['address'] + $register['size'] * $offset), $length, $pdu_address,($offset>27));
        return $return_data ;
    }
    /**
     *
     * Retrieve data from a group
     *
     * @param   register name,
     *          phase to be accessed
     *          complete string/array of all the values within a group
     * @access  private
     * @return  measured value
     *
     */
    private function _readRawData($register, $phase, $RawData)
    {
        $StartIndex = ($register['address']+($phase*$register['size']))-$register['register'];
        //$this->log_print(  "<br> StartIndex = ". $StartIndex);  //debug feature

        //$this->log_print(  "register size: ". $register['size']); //debug feature
        $result_data = array_slice($this->ascii_to_array($RawData), $StartIndex, $register['size']);

        // Convert the array to a string of bytes
        return $this->array_to_ascii($result_data);
    }

    /*
     * Get specific data from a register, either with available data or by collecting a new block
     *
     */
    private function _getPDUdata($register, $phase, $pdu_address, $RawData)
    {
        if ($phase <= 0)
        {
            $phase = 0;
        }
        else
        {
            $phase--;	// The input is lowerd by one,
            //because the user starts counting at one, while the system starts at zero.
        }
        // choose _readRawData if the fourth input is given, choose _readRegister otherwise
        if (empty($RawData) )
        {
            $return_data = $this->_readRegister($register, $phase, $pdu_address);
        }
        else
        {
            if(strlen($RawData) == $register['register_length'])
            {
                $return_data = $this->_readRawData($register, $phase, $RawData);
            }
            else
            {
                $this->log_print("RawData doesnt match the expected length, expected ". $register['register_length']. " received " . strlen($RawData));
                return '';
            }
        }

        if(!empty($return_data) )
        {
            if ($register['type'] == "int")
            {  // Int register
                if($register['size'] == 1)
                {
                    $return_data = implode(unpack("C", $return_data));
                }
                elseif($register['size'] == 3)
                {
                    $return_data = implode(unpack("V", $return_data."\x00")); // Pad to 4 bytes with MSB=0 (Little endian)
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
    }


    /**
     *
     * Renumber PDU`s
     * Tested and adjusted: LFB 2016-07-05
     * !!NOTE!! This function isnt perfect, it sometimes fails
     * !!NOTE!! Always do a manual check afterwards
     */
    public function Renumber( $start_pdu_address = 1)
    {
        // Start first a scan_bus. You want to know which PDU`s are connected.
        // Read of every PDU the serial number
        // As last, write the new address. The new address depends on the serialnumber

        if ($this->debugging == true)
            $this->log_print( ( "INFO: Renumber: Start scan bus"));

        $FoundPDUs = $this->ScanBus();

        if (empty($FoundPDUs) && is_array($FoundPDUs))
        {
            if ($this->debugging == true)
                $this->log_print( ( "ERROR: Renumber: No PDU`s found"));
            return false;
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
                    if($this->debugging == true && !empty($pdu_hardware_address) && is_array($pdu_hardware_address))
                    {
                        $pdu_hardware_address_string = "";
                        foreach($pdu_hardware_address as $hardware_address)
                        {
                            $pdu_hardware_address_string .= $hardware_address;
                        }
                        $this->log_print( ( "INFO: Renumber: Write new pdu address: ".$start_pdu_address." to the PDU with serial number: ".$pdu_hardware_address_string));
                    }

                    // write new address
                    $result = $this->RawWriteRenumber($pdu_hardware_address, $start_pdu_address);

                    if($result == false)
                    {
                        $this->log_print("Writing new pdu address ( $start_pdu_address ) has failed");
                        $this->log_print("User is advised to check the PDU adress manually because this errorcheck is not perfect");
                    }

                    $start_pdu_address++;
                }
            }
            else
            {
                if ($this->debugging == true)
                    $this->log_print( ( "ERROR: Renumber: collection PDU serial number is empty"));
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
        $command = $this->_command['broadcast_write'];

        // Construct message (STX byte, command etc)
        $message = pack("C2v2",
            $this->_stx,
            $command,
            $register['address'],
            $offset);

        // Add truncated data to message
        $message .= $data;

        // Pack the transmit message, including rc4 and checksum
        $tx_msg = $this->_packTX_MSG($message);

        $tries = 0;
        $write = FALSE;

        $write = fwrite(($this->fp), $tx_msg);
        if($write != false)
            $rx_msg = fread(($this->fp),512);
        else
        {
            while ((!$write) && ($tries < $this->max_retry))
            {
                $this->Connect();
                if ($this->fp){
                    $write = fwrite(($this->fp), $tx_msg);
                    if($write != false)
                        $rx_msg = fread(($this->fp),512);
                }
                $tries++;
            }
            if ($this->debugging == true)
                $this->log_print("Tries required: $tries ");
        }
        return $write;
    }


    /*
     * Firmware upgrade
	 *
	 * Note: This function sends some of its output to the screen/outputbuffer in order to
	 *       provide feedback on the progress of the update.
     */
    public function FWUpgrade($binfile)
    {
        $version = "";
        $file_length = 0;
        $cs = "";
        $crc = "";
        $buffer = null;
        $fld = null;

        // Save the yield and timeout values to restore them after the upgrade
        $temp_yield = $this->yield;
        $temp_socket_timeout_s = $this->socket_timeout_s;
        $temp_socket_timeout_us = $this->socket_timeout_us;
        // Set yield and timeout low in order to speed up the upgrade
        // This assumes that no other system is trying to connect to the hPDU
        $this->yield = 0;//100000;
        $this->socket_timeout_s = 0;
        $this->socket_timeout_us = 250000; //100000 results in occasional loss of connection,250000 seems safe

        $matches = NULL;
        $pattern = '/SPFW-(\d{4})-(\S{8})-(\S{4}).*.bin/';
        preg_match($pattern, $binfile, $matches); #must match filename, such as SPFW-0140-004B7929-FE4D_Firmware_RCANDIDATE.bin

        if(!empty($matches))
        {
            $version    = (int)$matches[1];           // from 0130 to 130 (string)
            $checksum   = $matches[2];
            $crc        = $matches[3];

            print ("Firmware upgrade started to version $version. This may take 10 minutes. <br> \n");
            if ($this->debugging == true)
                $this->log_print("Firmware upgrade started to version $version.");

            // convert to hex
            $_crc       = trim(hexdec($crc));
            $_checksum  = trim(hexdec($checksum));

            // Open file
            $fh = fopen($binfile, 'r');

            // Get file length
            $file_size = filesize($binfile);

            // Create array for packets in order to Read file in pieces
            $packets = array();

            while (!feof($fh))
            {
                $packets[count($packets)] = fread($fh, 256);
            }
            // Close file
            fclose($fh);

            // Count the amount of packets that have to be send
            $amount_of_packets = (int) ($file_size/256) + 1;
            print ("Firmware Upgrade: Number of upgrade count of packets to be send = $amount_of_packets <br> \n");
            if ($this->debugging == true)
                $this->log_print("Firmware Upgrade: Number of upgrade count of packets to be send = $amount_of_packets");

            // Send the SPbus frame which announces the upgrade to the hPDU
            $register = $this->getRegisterByName('upvers');
            $msg = pack("vVvvV", $version, $_checksum, $_crc, $amount_of_packets, $file_size);

            $this->Connect();
            if($this->writeBroadcast($register, $msg, strlen($msg)) === false)
            {
                print ( "Firmware Upgrade: upgrade announcement frame failed<br> \n");
                if ($this->debugging == true)
                    $this->log_print("Firmware Upgrade: upgrade announcement frame failed");
            }
            else
            {
                print("Firmware Upgrade: sent header, waiting...<br> \n");
                if ($this->debugging == true)
                    $this->log_print("Firmware Upgrade: sent header, waiting...");

                $register = $this->getRegisterByName('upblnr');

                foreach ($packets as $i => $value)
                {
                    if (($i % 50) == 0)
                    {
                        print("Firmware Upgrade: sent packet $i of ".count($packets)."<br>\n");
                        if ($this->debugging == true)
                            $this->log_print( "Firmware Upgrade: sent packet $i of ".count($packets)."");
                    }

                    $msg = pack("v", $i) . $value;

                    if($this->writeBroadcast($register, $msg, strlen($msg)) == False)
                    {
                        print( "Firmware Upgrade: Packet $i failed. <br>\n");
                        $this->log_print( "Firmware Upgrade: Packet $i failed. <br>\n");
                    }
                    else
                    {
                        if ($this->debugging == true)
                            $this->log_print( "Firmware Upgrade: sent packet: $i.");
                    }

                    // The upgrade process may take more time than the Maximum Execution Time
                    // set_time_limit is used to reset the  Timer, and does not work in PHP safe mode
                    flush();
                    set_time_limit(120);
                }
            }

            print("Firmware Upgrade: sent packets, waiting...<br> \n");
            if ($this->debugging == true)
                $this->log_print( "Firmware Upgrade: sent packets, waiting...");

            usleep(1000000);

            print("Firmware Upgrade: rebooting unit...<br> \n");
            if ($this->debugging == true)
                $this->log_print("Firmware Upgrade: rebooting unit...");


            $boot = pack("C", 1);
            $register = $this->getRegisterByName('rsboot');
            $this->writeBroadcast($register, $boot, 1);

            print ("Firmware Upgrade: reboot done in a few seconds...<br> \n");
            if ($this->debugging == true)
                $this->log_print("Firmware Upgrade: reboot done in a few seconds...");

            // Return yield and timeout to their original values
            $this->yield = $temp_yield;
            $this->socket_timeout_s = $temp_socket_timeout_s;
            $this->socket_timeout_us = $temp_socket_timeout_us;
            return 1;
        }
        else
        {
            print("The file($binfile) does not match the required pattern.<br> \n");
            if ($this->debugging == true)
                $this->log_print( "The file($binfile) does not match the required pattern.");
        }
        // Return yield and timeout to their original values
        $this->yield = $temp_yield;
        $this->socket_timeout_s = $temp_socket_timeout_s;
        $this->socket_timeout_us = $temp_socket_timeout_us;
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
        // The checksum consists of 2 empty bytes and 2 checksum bytes
        // Therefore it could be considered to be a 16bit checksum in a 32bit frame
        $sum = 0;

        for ($i = 0; $i < strlen($data); $i++)
        {

            $sum += ord($data[$i]);
        }


        return $sum % 0xFFFF;
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
                $this->log_print( ( "Register not found"));
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
        $register = $this->getRegisterByName("swounl");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address);

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
    public function getPDUDatamodelVersion($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("idspdm");
        return $this->_getPDUdata($register, 0, $pdu_address, $RawData);
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
    public function getPDUFirmwareVersion($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("idfwvs");
        return $this->_getPDUdata($register, 0, $pdu_address, $RawData);
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
    public function getPDUSalesOrderNumber($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("idonbr");
        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUProductId($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("idpart");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUSerialNumber($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("idsnbr");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUHardwareAddress($pdu_address, $return_as_integer = FALSE, $RawData = 0)
    {
        $register = $this->getRegisterByName("idchip");

        // If TRUE: This function returns the data as an array, otherwise as an string.
        if($return_as_integer === TRUE)
        {
            $settings_bytes = $register['channels'] * $register['size'];

            $datablock = $this->ReadRaw($register['address'], $settings_bytes, $pdu_address);

            // Unpack the register block to a byte array
            $register_block_byte_array = unpack("C*", $datablock);

            if (count($register_block_byte_array) <= 0)
            {
                $this->log_print("WARNING: Register_block does not contain any item! $pdu_address");
                return null;
            }
            if (count($register_block_byte_array) == 1)
            {
                // This is an error code instead of a register block
                $error_code = $register_block_byte_array[1] - 256;
                $this->log_print("WARNING: Obtained errorcode $error_code while parsing registers of $pdu_address and register ".$register['address']);
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
            if(empty($RawData))
            {
                // Collect the entire identification block, otherwise the _getPDUdata raises an error
                $datablock = $this->ReadRaw($register['register'], $register['register_length'], $pdu_address);
            }
            else
                $datablock = $RawData;
            // The second argument of _getPDUdata is the register number,
            //  which is incremented by one in order to comply with the _getPDUdata function
            $value_1 = $this->_getPDUdata($register, 1, $pdu_address, $datablock);
            $value_2 = $this->_getPDUdata($register, 2, $pdu_address, $datablock);
            $value_3 = $this->_getPDUdata($register, 3, $pdu_address, $datablock);

            $value = $value_1 . "-".$value_2 . "-".$value_3;
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
    public function getPDUUnitAddress($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("idaddr");

        return $this->_getPDUdata($register, 0, $pdu_address, $RawData);
    }
    public function getPDUPhaseTotal($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("cfnrph");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUOutletTotal($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("cfnrno");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUSwitchedOutletTotal($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("cfnrso");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUMeasuredOutletTotal($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("cfnrmo");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUMaximumLoad($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("cfamps");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUTemperatureSensorTotal($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("cfnrte");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUDeviceStatusCode($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("ssstat");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUTemperatureAlert($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("ssttri");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUInputCurrentAlert($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("ssitri");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUOutputCurrentAlert($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("ssotri");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUInputVoltageAlert($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("ssvtri");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUFuseBlownAlert($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("ssftri");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    /* Get blown fuse alert


    */

    public function getPDUiCurrentAlert($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("ssicda");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    public function getPDUoCurrentAlert($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("ssftri");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    public function getPDUsensorChangeAlert($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("sssnsa");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    public function getPDUoVoltageDropAlert($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("ssovda");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUDeviceName($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stdvnm");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUDeviceLocation($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stdvlc");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUVanityTag($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stuser");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUPeakDuration($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stpkdr");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;

    }
    /**
     *
     * Get PDU Extended names Setting
     * This changes the namelengths to 18 characters
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUExtendedNamesSetting($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stextn");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUFixedOutletDelay($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stfodl");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUPowerSaverMode($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stpsav");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUOutletPowerupMode($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stopom");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUMaximumTemperature($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stmaxt");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUDisplayOrientation($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stdiso");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUMaximumInletAmps($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stimcm");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUOutletMaximumAmps($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stomcm");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUOutletDelay($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("stiodl");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }

    /**
     *
     * Get autoreset Alerts Setting
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getAutoResetAlerts($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("starsa");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }

    /**
     *
     * Get PDU outlet state
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUOutletState($pdu_address, $pdu_channel, $RawData = 0)
    {
        $register = $this->getRegisterByName("swocst");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

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
    public function getPDUOutletScheduledActivity($pdu_address, $pdu_channel, $RawData = 0)
    {
        $register = $this->getRegisterByName("swosch");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

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
    public function getPDUkWhTotal($pdu_address, $phase = 0, $RawData = 0)
    {

        $register = $this->getRegisterByName("imkwht");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
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
    public function getPDUkWhSubtotal($pdu_address, $phase = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("imkwhs");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
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
    public function getPDUPowerFactor($pdu_address, $phase = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("impfac");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
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
    public function getPDUActualCurrent($pdu_address, $phase = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("imcrac");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
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
    public function getPDUPeakCurrent($pdu_address, $phase = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("imcrpk");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
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
    public function getPDUActualVoltage($pdu_address, $phase = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("imvoac");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
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
    public function getPDULowestVoltage($pdu_address, $phase = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("imvodp");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
    }
    public function getPDUWhSubtotalfraction($pdu_address, $phase = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("imwkhf");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
    }

    public function getPDUExtendedInputName($pdu_address, $phase = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("imname");
        return $this->_getPDUdata($register, $phase, $pdu_address, $RawData);
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
    public function getPDUOutletkWhTotal($pdu_address, $pdu_channel = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("omkwht");
        return $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);
    }

    public function getPDUSensorValue($pdu_address, $pdu_channel, $RawData = 0)
    {
        $register = $this->getRegisterByName("snsval");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

        return $value;
    }

    public function getPDUSensorType($pdu_address, $pdu_channel, $RawData = 0)
    {
        $register = $this->getRegisterByName("snstyp");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

        return $value;
    }

    public function getPDUOutputCTratio($pdu_address, $pdu_channel, $RawData = 0)
    {
        $register = $this->getRegisterByName("stomct");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

        return $value;
    }

    public function getPDUInputCTratio($pdu_address, $pdu_channel, $RawData = 0)
    {
        $register = $this->getRegisterByName("stimct");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

        return $value;
    }

    public function getPDUInputName($pdu_address, $pdu_channel, $RawData = 0)
    {
        $register = $this->getRegisterByName("stinnm");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

        return $value;
    }

    public function getPDUOutletName($pdu_address, $pdu_channel, $RawData = 0)
    {
        $register = $this->getRegisterByName("stolnm");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

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
    public function getPDUOutletkWhSubtotal($pdu_address, $pdu_channel = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("omkwhs");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

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
    public function getPDUOutletPowerFactor($pdu_address, $pdu_channel = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("ompfac");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

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
    public function getPDUOutletActualCurrent($pdu_address, $pdu_channel = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("omcrac");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

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
    public function getPDUOutletPeakCurrent($pdu_address, $pdu_channel = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("omcrpk");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

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
    public function getPDUOutletActualVoltage($pdu_address, $pdu_channel = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("omvoac");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

        return $value;
    }
    public function getPDUOutletsuWhSubtotal($pdu_address, $pdu_channel = 0, $RawData = 0)
    {
        $register = $this->getRegisterByName("omuwhs");

        $value = $this->_getPDUdata($register, $pdu_channel, $pdu_address, $RawData);

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
    public function getPDUInternalTemperature($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("pditem");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUExternalTemperature($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("pdetem");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    public function getPDUdataBlockNumber($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("upblnr");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    public function getPDUdataBlock($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("updata");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUInternalPeakTemperature($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("pdinpk");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUExternalPeakTemperature($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("pdexpk");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

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
    public function getPDUInletTotal($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("cfnrph");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }


    /**
     * Set the type of PDU connection.
     * These options are available: GATEWAY | SERIAL_PORT | TCP_IP_CONVERTER
     *
     * @param string $type_pdu_connection
     */
    /*     public function setTypePDUConnection($type_pdu_connection = "GATEWAY")
        {
            $this->type_pdu_connection = $type_pdu_connection;

            return TRUE;
        }
         */
    /**
     *
     * Get PDU environment sensors
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUSensorName($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("snsnme");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    /**
     *
     * Get PDU Extended Sensor Name
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUExtendedSensorName($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("snsenm");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    /**
     *
     * Get PDU Extended Outlet Name
     *
     * @param int $pdu_address
     * @access public
     * @return int
     *
     */
    public function getPDUExtendedOutletName($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("exolnm");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }

    public function getPDUversion($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("upvers");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }

    // 2016-07-12 Cant verify the functionality of getFirmwareIsValid: it always returns NULL
    public function getFirmwareIsValid($pdu_address, $RawData = 0)
    {
        $register = $this->getRegisterByName("upckok");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }

    public function getPDUNumberOfEnvSensors($pdu_address, $RawData = 0)
    {

        $register = $this->getRegisterByName("cfnres");

        $value = $this->_getPDUdata($register, 0, $pdu_address, $RawData);

        return $value;
    }
    /**
     * Get Ring Status
     * @return 1 = OK, 0 = failure, 2 = not enabled
     * Works with hpdu version >= 2.34 and Gateway version >= 2.54
     **/
    public function getRingStatus()
    {
        $register = $this->getRegisterByName("horist");

        // $phase and $pdu_adress are 0: this way the parent PDU is selected
        $value = $this->_getPDUdata($register, 0, 0);

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

                $this->log_print( ( "Error code: ".$error_code.", Source: ".$source.", Message: ".$message));
            }
            else
            {
                // No good value
                // value must be lower than 0
            }
        }
        catch (Exception $ex)
        {
            $this->log_print( ( "Exception: ".$ex->getMessage().", Data: ".$data));
        }

    }
}

?>
