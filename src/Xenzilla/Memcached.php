<?php

/**
 * An all PHP implementation of the PECL memcached extension
 * with SASL PLAIN Auth support
 *
 * @license
 * Copyright 2013 Benedikt Bauer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

namespace Xenzilla;


class Memcached
{
    // Options
    const OPT_COMPRESSION = -1001;
    const OPT_SERIALIZER = -1003;
    const SERIALIZER_PHP = 1;
    const SERIALIZER_IGBINARY = 2;
    const SERIALIZER_JSON = 3;
    const OPT_PREFIX_KEY = -1002;
    const OPT_HASH = 2;
    const HASH_DEFAULT = 0;
    const HASH_MD5 = 1;
    const HASH_CRC = 2;
    const HASH_FNV1_64 = 3;
    const HASH_FNV1A_64 = 4;
    const HASH_FNV1_32 = 5;
    const HASH_FNV1A_32 = 6;
    const HASH_HSIEH = 7;
    const HASH_MURMUR = 8;
    const OPT_DISTRIBUTION = 9;
    const DISTRIBUTION_MODULA = 0;
    const DISTRIBUTION_CONSISTENT = 1;
    const OPT_LIBKETAMA_COMPATIBLE = 16;
    const OPT_BUFFER_WRITES = 10;
    const OPT_BINARY_PROTOCOL = 18;
    const OPT_NO_BLOCK = 0;
    const OPT_TCP_NODELAY = 1;
    const OPT_SOCKET_SEND_SIZE = 4;
    const OPT_SOCKET_RECV_SIZE = 5;
    const OPT_CONNECT_TIMEOUT = 14;
    const OPT_RETRY_TIMEOUT = 15;
    const OPT_SEND_TIMEOUT = 19;
    const OPT_RECV_TIMEOUT = 15;
    const OPT_POLL_TIMEOUT = 8;
    const OPT_CACHE_LOOKUPS = 6;
    const OPT_SERVER_FAILURE_LIMIT = 21;
    const HAVE_IGBINARY = -1004;
    const HAVE_JSON = -1005;
    const GET_PRESERVE_ORDER = 1;

    // Result codes
    const RES_SUCCESS = 0;
    const RES_NOTFOUND = 1;

    // Value Type Flags
    const MEMC_VAL_TYPE_MASK = 0xf;
    const MEMC_VAL_IS_STRING = 0;
    const MEMC_VAL_IS_LONG = 1;
    const MEMC_VAL_IS_DOUBLE = 2;
    const MEMC_VAL_IS_BOOL = 3;
    const MEMC_VAL_IS_SERIALIZED = 4;
    const MEMC_VAL_COMPRESSED = 16; // 2^4

    protected $responseFormat = 'Cmagic/Copcode/nkeylength/Cextralength/Cdatatype/nstatus/Nbodylength/NOpaque/NCAS1/NCAS2';
    protected $requestFormat = 'CCnCCnNNNN';

    protected $servers = array();

    protected $responseStatus = 0;

    protected $options = array
    (
        Memcached::OPT_SERIALIZER => Memcached::SERIALIZER_PHP,
        Memcached::OPT_COMPRESSION => FALSE,
//        HAVE_JSON => version_compare(phpversion(), '5.2.10'),
//        HAVE_IGBINARY => extension_loaded('igbinary'),
    );

    protected $persistent_id = '';

    protected $connection;

    protected $queue = array();

    /**
     *
     */
    public function __construct($persistent_id = '')
    {
        if ($persistent_id !== '')
        {
            $this->persistent_id = $persistent_id;
        }
    }

    /**
     *
     */
    protected function prepareSend($value)
    {
        $flag = 0;

        if (is_string($value))
        {
            $flag |= self::MEMC_VAL_IS_STRING;
        }
        elseif (is_long($value))
        {
            $flag |= self::MEMC_VAL_IS_LONG;
        }
        elseif (is_double($value))
        {
            $flag |= self::MEMC_VAL_IS_DOUBLE;
        }
        elseif (is_bool($value))
        {
            $flag |= self::MEMC_VAL_IS_BOOL;
        }
        else
        {
            switch($this->options[self::OPT_SERIALIZER])
            {
                case self::SERIALIZER_PHP:
                    $value = serialize($value);
                    break;

                case self::SERIALIZER_IGBINARY:
                    $value = igbinary_serialize($value);
                    break;

                case self::SERIALIZER_JSON:
                    $value = json_encode($value);
                    break;
            }

            $flag |= self::MEMC_VAL_IS_SERIALIZED;
        }

        if (array_key_exists(self::OPT_COMPRESSION, $this->options) && $this->options[self::OPT_COMPRESSION])
        {
            $flag |= self::MEMC_VAL_COMPRESSED;
            $value = gzcompress($value);
        }

        return array($flag, $value);
    }

    /**
     *
     */
    protected function send($data)
    {
        $valuelength = $extralength = $keylength = 0;

        if (array_key_exists('extra', $data))
        {
            $extralength = strlen($data['extra']);
        }

        if (array_key_exists('key', $data))
        {
            $keylength = strlen($data['key']);
        }

        if (array_key_exists('value', $data))
        {
            $valuelength = strlen($data['value']);
        }

        $bodylength = $extralength + $keylength + $valuelength;

        $request = pack(
            $this->requestFormat,
            0x80,
            $data['opcode'],
            $keylength,
            $extralength,
            array_key_exists('datatype', $data) ? $data['datatype'] : null,
            array_key_exists('status', $data) ? $data['status'] : null,
            $bodylength,
            array_key_exists('Opaque', $data) ? $data['Opaque'] : null,
            array_key_exists('CAS1', $data) ? $data['CAS1'] : null,
            array_key_exists('CAS2', $data) ? $data['CAS2'] : null
        );

        if (array_key_exists('extra', $data))
        {
            $request .= $data['extra'];
        }

        if (array_key_exists('key', $data))
        {
            $request .= $data['key'];
        }

        if (array_key_exists('value', $data))
        {
            $request .= $data['value'];
        }

        if (!isset($this->connection))
        {
            //TODO implement spreading across servers
            $this->connection = stream_socket_client($this->servers[0]['host'].':'.$this->servers[0]['port']);
        }

        $sent = fwrite($this->connection, $request);

        return $sent;
    }

    /**
     *
     */
    protected function recv()
    {
        $data = fread($this->connection, 24);

        if ($data == '')
        {
            throw new \LogicException('No Response from Memcached');
        }

        $response = unpack($this->responseFormat, $data);
        if (array_key_exists('bodylength', $response))
        {
            $bodylength = $response['bodylength'];
            $data = '';
            while ($bodylength > 0)
            {
                $binData = fread($this->connection, $bodylength);
                $bodylength -= strlen($binData);
                $data .= $binData;
            }
            if (array_key_exists('extralength', $response) && $response['extralength'] > 0)
            {
                $extra = unpack('Nint', substr($data, 0, $response['extralength']));
                $response['extra'] = $extra['int'];
            }

            $response['key'] = substr($data, $response['extralength'], $response['keylength']);
            $response['body'] = substr($data, $response['extralength'] + $response['keylength']);
        }
        return $response;
    }

    /**
     *
     */
    public function add($key, $value, $expiration = 0)
    {
        list($flag, $value) = $this->prepareSend($value);
        $extra = pack('NN', $flag, $expiration);
        $this->send(
            array(
                'opcode' => 0x02,
                'key' => $key,
                'value' => $value,
                'extra' => $extra,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }
        return FALSE;
    }

    /**
     *
     */
    public function addByKey($server_key, $key, $value, $expiration = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    protected function compareWeight($a, $b)
    {
        if ($a['weight'] == $b['weight'])
        {
            return 0;
        }
        return ($a['weight'] < $b['weight']) ? 1 : -1;
    }

    /**
     *
     */
    public function addServer($host, $port, $weight = 0)
    {
        $this->servers[] = array
        (
            'host' => $host,
            'port' => $port,
            'weight' => $weight,
        );

        usort($this->servers, array($this, 'compareWeight'));

        return TRUE;
    }

    /**
     *
     */
    public function addServers($servers)
    {
        $this->servers = array_merge($this->servers, $servers);
        usort($this->servers, array($this, 'compareWeight'));

        return TRUE;
    }

    /**
     *
     */
    public function append($key, $value)
    {
        if ($this->options[self::OPT_COMPRESSION])
        {
            return FALSE;
        }

        $this->send(
            array(
                'opcode' => 0x0e,
                'key' => $key,
                'value' => $value,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }

        return FALSE;
    }

    /**
     *
     */
    public function appendByKey($server_key, $key, $value)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    protected function upper($num)
    {
        return $num << 32;
    }

    protected function lower($num)
    {
        return $num % (2 << 32);
    }

    /**
     *
     */
    public function cas($cas_token, $key, $value, $expiration = 0)
    {
        $cas1 = $this->upper($cas_token);
        $cas2 = $this->lower($cas_token);

        list($flag, $value) = $this->prepareSend($value);
        $extra = pack('NN', $flag, $expiration);
        $this->send(
            array(
                'opcode' => 0x01,
                'key' => $key,
                'value' => $value,
                'extra' => $extra,
                'CAS1' => $cas1,
                'CAS2' => $cas2,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }
        return FALSE;
    }

    /**
     *
     */
    public function casByKey($cas_token, $server_key, $key, $value, $expiration = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    protected function shift($key, $offset, $initial_value, $expiry)
    {
        $initial_value = 0;

        $opcode = 0x05;
        if ($offset < 0)
        {
            $opcode = 0x06;
            $offset = $offset * -1;
        }

        $extra = pack('N2N2N', $this->upper($offset), $this->lower($offset), $this->upper($initial_value), $this->lower($initial_value), $expiry);
        $this->send(
            array(
                'opcode' => $opcode,
                'key' => $key,
                'extra' => $extra,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }

        return FALSE;
    }

    /**
     *
     */
    public function decrement($key, $offset = 1, $initial_value = 0, $expiry = 0)
    {
        return $this->shift($key, $offset*-1, $initial_value, $expiry);
    }

    /**
     *
     */
    public function decrementByKey($server_key, $key, $offset = 1, $initial_value = 0, $expiry = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function delete($key)
    {
        $this->send(
            array(
                'opcode' => 0x04,
                'key' => $key,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }

        return FALSE;
    }

    /**
     *
     */
    public function deleteByKey($server_key, $key, $time = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function deleteMulti($keys)
    {
        $success = TRUE;

        foreach($keys as $key)
        {
            if (!$this->delete($key))
            {
                $success = FALSE;
            }
        }

        return $success;
    }

    /**
     *
     */
    public function deleteMultiByKey($server_key, $keys, $time = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function fetch()
    {
        if (count($this->queue) == 0)
        {
            return FALSE;
        }

        $item = array_shift($this->queue[0]);
        if ($item === null)
        {
            return FALSE;
        }

        $result = array('key' => $item);
        if ($this->queue[1])
        {
            $result['value'] = $this->get($item, null, $result['cas']);
        }
        else
        {
            $result['value'] = $this->get($item);
        }

        return $result;
    }

    /**
     *
     */
    public function fetchAll()
    {
        if (count($this->queue) == 0)
        {
            return FALSE;
        }

        $results = array();

        $keys = $this->queue[0];
        foreach ($keys as  $key)
        {
            $result = array('key' => $key);
            if ($this->queue[1])
            {
                $result['value'] = $this->get($key, null, $result['cas']);
            }
            else
            {
                $result['value'] = $this->get($key);
            }

            $results[] = $result;
        }

        return (count($results) > 0);
    }

    /**
     *
     */
    public function flush($delay = 0)
    {
        $this->send(
            array(
                'opcode' => 0x08,
                'extras' => $delay,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }

        return FALSE;
    }

    /**
     *
     */
    protected function parseResponse($data)
    {
        if (!array_key_exists('extra', $data))
        {
            throw new \LogicException('Not a valid Response stored by Xenzilla\Memcached');

        }

        if ($data['extra'] & self::MEMC_VAL_COMPRESSED)
        {
            $body = gzuncompress($data['body']);
        }
        else
        {
            $body = $data['body'];
        }

        $type = $data['extra'] & self::MEMC_VAL_TYPE_MASK;

        switch ($type)
        {
            case self::MEMC_VAL_IS_STRING:
                $body = strval($body);
                break;

            case self::MEMC_VAL_IS_LONG:
                $body = intval($body);
                break;

            case self::MEMC_VAL_IS_DOUBLE:
                $body = doubleval($body);
                break;

            case self::MEMC_VAL_IS_BOOL:
                $body = $body ? TRUE : FALSE;
                break;

            case self::MEMC_VAL_IS_SERIALIZED:
                switch ($this->options[self::OPT_SERIALIZER])
                {
                    case self::SERIALIZER_PHP:
                        $body = unserialize($body);
                        break;

                    case self::SERIALIZER_IGBINARY:
                        $body = igbinary_unserialize($body);
                        break;

                    case self::SERIALIZER_JSON:
                        $body = json_decode($body);
                        break;
                }
                break;
        }

        return $body;
    }

    /**
     *
     */
    public function get($key, $cache_cb = null, &$cas_token = null)
    {
        $this->send(
            array(
                'opcode' => 0x00,
                'key' => $key,
            )
        );

        $data = $this->recv();
        if (array_key_exists('status', $data))
        {
            $this->responseStatus = $data['status'];
            if ($this->responseStatus == 0)
            {
                return $this->parseResponse($data);
            }
        }
        return FALSE;
    }

    /**
     *
     */
    public function getAllKeys()
    {
        // No corresponding Memcached Binary protocol function
        return FALSE;
    }

    /**
     *
     */
    public function getByKey($server_key, $key, $cache_cb = null, &$cas_token = null)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function getDelayed($keys, $with_cas = FALSE, $value_cb = null)
    {
        $this->queue = array($keys, $with_cas);

        $success = TRUE;

        if ($value_cb != null)
        {
            foreach($keys as $key)
            {
                if (call_user_func_array($value_cb, array($this, $key)) === FALSE)
                {
                    $success = FALSE;
                }
            }
        }

        return $success;
    }

    /**
     *
     */
    public function getDelayedByKey($server_key, $keys, $with_cas = FALSE, $value_cb = null)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function getMulti($keys, &$cas_tokens = null, $flags = null)
    {
        $results = array();
        $tokens = array();
        foreach ($keys as $key)
        {
            $token = 0.0;
            $result = $this->get($key, null, $token);
            if ($result !== FALSE)
            {
                $reults[$key] = $result;
                $tokens[$key] = $token;
            }
        }

        if($cas_tokens !== null)
        {
            $cas_tokens = $tokens;
        }

        return empty($results) ? FALSE : $results;
    }

    /**
     *
     */
    public function getMultiByKey($server_key, $keys, &$cas_tokens = null, $flags = null)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function getOption($option)
    {
        if (array_key_exists($option, $this->options))
        {
            return $this->options[$option];
        }
        return FALSE;
    }

    /**
     *
     */
    public function getResultCode()
    {
        return $this->responseStatus;
    }

    /**
     *
     */
    public function getResultMessage()
    {
        // TODO Return result messages
        return "";
    }

    /**
     *
     */
    public function getServerByKey($server_key)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function getServerList()
    {
        return $this->servers;
    }

    /**
     *
     */
    public function getStats()
    {

    }

    /**
     *
     */
    public function getVersion()
    {
        $this->send(
            array(
                'opcode' => 0x0b,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return strval($data['body']);
        }
        return false;
    }

    /**
     *
     */
    public function increment($key, $offset = 1, $initial_value = 0, $expiry = 0)
    {
        return $this->shift($key, $offset, $initial_value, $expiry);
    }

    /**
     *
     */
    public function incrementByKey($server_key, $key, $offset = 1, $initial_value = 0, $expiry = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function isPersistent()
    {
        return $this->persistent_id != '';
    }

    /**
     *
     */
    public function isPristine()
    {
        return !isset($this->connection);
    }

    /**
     *
     */
    public function prepend($key, $value)
    {
        if ($this->options[self::OPT_COMPRESSION])
        {
            return FALSE;
        }

        $this->send(
            array(
                'opcode' => 0x0f,
                'key' => $key,
                'value' => $value,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }

        return FALSE;
    }

    /**
     *
     */
    public function prependByKey($server_key, $key, $value)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function quit()
    {
        $this->send(
            array(
                'opcode' => 0x07,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }

        return FALSE;
    }

    /**
     *
     */
    public function replace($key, $value, $expiration = 0)
    {
        list($flag, $value) = $this->prepareSend($value);

        $extra = pack('NN', $flag, $expiration);
        $this->send(
            array(
                'opcode' => 0x03,
                'key' => $key,
                'value' => $value,
                'extra' => $extra,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return TRUE;
        }

        return FALSE;
    }

    /**
     *
     */
    public function replaceByKey($server_key, $key, $value, $expiration = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function resetServerList()
    {
        $this->servers = array();
    }

    /**
     *
     */
    public function set($key, $value, $expiration = 0)
    {
        list($flag, $value) = $this->prepareSend($value);

        $extra = pack('NN', $flag, $expiration);
        $this->send(
            array(
                'opcode' => 0x01,
                'key' => $key,
                'value' => $value,
                'extra' => $extra,
            )
        );

        $data = $this->recv();
        $this->responseStatus = $data['status'];
        if ($this->responseStatus == 0)
        {
            return $data;
        }

        return FALSE;
    }

    /**
     *
     */
    public function setByKey($server_key, $key, $value, $expiration = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function setMulti($items, $expiration = 0)
    {
        $success = true;

        foreach($items as $key => $value)
        {
            if(!($this->set($key, $value, $expiration)))
            {
                $success = false;
            }
        }

        return $success;
    }

    /**
     *
     */
    public function setMultiByKey($server_key, $items, $expiration = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }

    /**
     *
     */
    public function setOption($option, $value)
    {
        $this->options[$option] = $value;
    }

    /**
     *
     */
    public function setOptions($options)
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     *
     */
    public function listMechanisms()
    {
        $this->send(array('opcode' => 0x20));
        $data = $this->recv();
        return explode(" ", $data['body']);
    }

    /**
     *
     */
    public function setSaslAuthData($user, $password)
    {
        $this->send(
            array(
                'opcode' => 0x21,
                'key' => 'PLAIN',
                'value' => '' . chr(0) . $user . chr(0) . $password
            )
        );
        $data = $this->recv();
        if (is_array($data) && array_key_exists('status', $data) && $data['status'] == 0)
        {
            return TRUE;
        }
        return FALSE;
    }

    /**
     *
     */
    public function touch($key, $expiration)
    {
        $this->send(
            array(
                'opcode' => 0x1c,
                'key' => $key,
                'extra' => $expiration,
            )
        );

        $data = $this->recv();
        if ($data['status'] === 0)
        {
            return TRUE;
        }
        return FALSE;
    }

    /**
     *
     */
    public function touchByKey($server_key, $key, $expiration = 0)
    {
        throw new \LogicException('Different Hashing Methods not yet implemented');
    }
}
