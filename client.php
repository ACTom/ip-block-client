#!/usr/bin/php
<?php
define('SUPPORT_IPV6', true);

class Base {
    protected function log($log) {
        $log_file = __DIR__ . "/client.log";
        $date = date("Y-m-d H:i:s");
        $log_str = "[{$date}] $log\n";
        file_put_contents($log_file, $log_str, FILE_APPEND);
        echo $log_str;
    }
}

class FirewalldPlugin extends Base{
    public function checkCanUse() {
        if (stristr(PHP_OS, 'LINUX') === false) {
            return false;
        }
        if (file_exists('/usr/bin/firewall-cmd')) {
            return true;
        }
        return false;
    }

    public function getExists() {
        exec('/usr/bin/firewall-cmd --list-rich-rules', $content);
        for ($i = 0; $i < count($content); $i++) {
            $content[$i] = str_replace('rule family="ipv4" source address="', '', $content[$i]);
            $content[$i] = str_replace('rule family="ipv6" source address="', '', $content[$i]);
            $content[$i] = str_replace('" reject', '', $content[$i]);
        }
        return $content;
    }

    private function getRule($ip, $is_ipv4 = true) {
        $ipv4 = $is_ipv4 ? 'ipv4' : 'ipv6';
        return "rule family='{$ipv4}' source address='{$ip}' reject";
    }

    public function add($ip, $is_ipv4 = true) {
        if ($ip == '') {
            return false;
        }
        $rule = $this->getRule($ip, $is_ipv4);
        $result = system("/usr/bin/firewall-cmd --permanent --add-rich-rule=\"{$rule}\"", $return_var);
        $this->log("Add {$ip}: {$result}");
        return true;
    }

    public function remove($ip, $is_ipv4 = true) {
        $ip = trim($ip);
        if ($ip == '') {
            return false;
        }
        $rule = $this->getRule($ip, $is_ipv4);
        $result = system("/usr/bin/firewall-cmd --permanent --remove-rich-rule=\"{$rule}\"", $return_var);
        $this->log("Remove {$ip}: {$result}");
        return true;
    }

    public function save() {
        system('/usr/bin/firewall-cmd --reload');
    }
}

class IptablesPlugin extends Base {
    public function checkCanUse() {
        if (stristr(PHP_OS, 'LINUX') === false) {
            return false;
        }
        if (file_exists('/usr/bin/firewall-cmd')) {
            return false;
        }
        if (file_exists('/sbin/iptables')) {
            return true;
        }
        return false;
    }

    public function getExists() {
        $ignores = array('0.0.0.0/0', '--', '::/0');
        exec('/sbin/iptables -L INPUT -n', $content);
        $result = array();
        foreach ($content as $item) {
            if (preg_match('/^DROP +all +\S+ +(\S+?) +?.+$/', $item, $matches) > 0) {
                $ip = $matches[1];
                if (!in_array($ip, $ignores)) {
                    $result [] = $ip;
                }
            }
        }
        if (SUPPORT_IPV6) {
            exec('/sbin/ip6tables -L INPUT -n', $content);
            foreach ($content as $item) {
                if (preg_match('/^DROP +all +(\S+?) +?.+$/', $item, $matches) > 0) {
                    $ip = $matches[1];
                    if (!in_array($ip, $ignores)) {
                        $result [] = $ip;
                    }
                }
            }
        }
        return $result;
    }

    private function getRule($ip, $is_ipv4 = true) {
        return "INPUT -s {$ip} -j DROP";
    }

    public function add($ip, $is_ipv4 = true) {
        $command = ($is_ipv4 ? '/sbin/iptables ' : '/sbin/ip6tables ') . '-I ' . $this->getRule($ip, $is_ipv4);
        $result = system($command, $return_var);
        $this->log("Add {$ip}: {$result}");
        return true;
    }

    public function remove($ip, $is_ipv4 = true) {
        $command = ($is_ipv4 ? '/sbin/iptables ' : '/sbin/ip6tables ') . '-D ' . $this->getRule($ip, $is_ipv4);
        $result = system($command, $return_var);
        $this->log("Remove {$ip}: {$result}");
        return true;
    }

    public function save() {
        system('/sbin/service iptables save');
    }
}

class WindowsPlugin extends Base {
    public function checkCanUse() {
        if (stristr(PHP_OS, 'WIN') !== false) {
            return true;
        }
        return false;
    }

    public function getExists() {
        exec('netsh advfirewall firewall show rule name="BLOCKED IP"', $content);
        $result = array();
        foreach ($content as $item) {
            if (preg_match('/^RemoteIP: +(\S+?)$/', $item, $matches) > 0) {
                if (preg_match('/^(.*?)[\/\-](.*)$/', $matches[1], $matches2) > 0){
                    $ip = $matches2[1];
                    $mask = $matches2[2];
                    if (is_numeric($mask) && $mask != '32') {
                        $ip .= "/{$mask}";
                    }
                    $result []= $ip;
                }
            }
        }
        return $result;
    }

    public function add($ip, $is_ipv4 = true) {
        exec("netsh advfirewall firewall add rule name=\"BLOCKED IP\" interface=any dir=in action=block remoteip={$ip}", $return_var);
        $this->log("Add {$ip}: {$return_var[0]}");
    }

    public function remove($ip, $is_ipv4 = true) {
        exec("netsh advfirewall firewall delete rule name=\"BLOCKED IP\" remoteip={$ip}", $return_var);
        $this->log("Remove {$ip}: {$return_var[0]}");
    }

    public function save() {}
}

class Client extends Base {
    private $firewall = null;
    private $pluginList = array();
    public function __construct() {
        $this->pluginList = array(new FirewalldPlugin(), new IptablesPlugin(), new WindowsPlugin());
        foreach ($this->pluginList as $item) {
            if ($item->checkCanUse()) {
                $this->firewall = $item;
                break;
            }
        }
        if (!$this->firewall) {
            $this->log('该系统不受支持！');
            exit;
        }
    }

    private function filterArray($arr) {
        $result = array();
        foreach ($arr as $item) {
            $item = trim($item);
            if ($item === '') {
                continue;
            }
            $result []= $item;
        }
        return $result;
    }

    private function getSource(&$i4, &$i6, &$white4, &$white6, &$exists) {
        $content = file_get_contents('https://blacklist.gcbidding.com/api.php?key=1x3d34dd321');
        $data = json_decode($content, true);
        if (!$data) {
            $this->log("获取IP列表失败！");
            exit();
        } else {
            $this->log("获取IP列表成功！");
        }
        $ipv4 = $data['ipv4'];
        $ipv6 = $data['ipv6'];
        $white4 = $data['white4'];
        $white6 = $data['white6'];

        $i4 = $this->filterArray(explode("\n", $ipv4));
        $i6 = $this->filterArray(explode("\n", $ipv6));
        $white4 = $this->filterArray(explode("\n", $white4));
        $white6 = $this->filterArray(explode("\n", $white6));
        $exists = $this->filterArray($this->firewall->getExists());
    }

    public function run() {
        $this->getSource($i4, $i6, $white4, $white6, $exists);
        $changed = false;

        
        /* 解除白名单 */
        $white_del = array_intersect($exists, $white4);
        foreach ($white_del as $item) {
            $this->firewall->remove($item);
            $changed = true;
        }
        if (SUPPORT_IPV6) {
            $white_del = array_intersect($exists, $white6);
            foreach ($white_del as $item) {
                $this->firewall->remove($item, false);
                $changed = true;
            }
        }

        /* 添加 ipv4 */
        $i4_insert = array_diff($i4, $white4, $exists);
        foreach ($i4_insert as $item) {
            $this->firewall->add($item);
            $changed = true;
        }
        /* 添加ipv6 */
        if (SUPPORT_IPV6) {
            $i6_insert = array_diff($i6, $white6, $exists);
            foreach ($i6_insert as $item) {
                $this->firewall->add($item, false);
                $changed = true;
            }
        }

        /* 如果有变动，更新firewalld */
        if ($changed) {
            $this->firewall->save();
        }
    }
}

date_default_timezone_set('Asia/Shanghai');

$client = new Client();
$client->run();