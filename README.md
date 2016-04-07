<h1 id="weblogincracker">web_login_cracker</h1>

<p>web登录爆破</p>

<hr>



<h2 id="用途">用途</h2>

<p>可用于爆破任何基于http/https协议使用get或post进行认证的网站 <br>
如：phpmyadmin,discuz,dedecms,phpcms等</p>

<h2 id="特性">特性</h2>

<ol>
<li>基于请求文件，可灵活适用于各种验证方式</li>
<li>可以修改代码实现base64编码或使用js脚本进行编码</li>
<li>意外中断程序后可以恢复爆破进度</li>
<li>适用于http和https协议</li>
<li>可通过使用<a href="http://drops.wooyun.org/tips/13043">简单验证码识别及工具编写思路 | WooYun知识库</a>中的验证码识别工具爆破有验证码的网站</li>
</ol>

<h2 id="需求">需求</h2>

<p>需要安装requests模块</p>

<h2 id="使用方法">使用方法</h2>

<ol>
<li>用burp suite等抓包工具获得登录原始请求</li>
<li>用<code>{%username%},{%password%},{%code%}</code>三个关键字分别替换掉登录请求中的用户名和密码和验证码（需要工具支持）</li>
<li><p>按下面的格式输入参数</p>
<pre><code>
<p>Usage: D:/web_login_cracker.py -r [request file] -u [usernames file] -p [passwords file] --error_password [error_password_signatures]</p>

<p>Options: <br>
  -h, ––help            show this help message and exit <br>
  -r REQUEST_FILE, ––req_file=REQUEST_FILE <br>
                        specify web login request file <br>
  -u USERNAMES_FILE, ––usernames_file=USERNAMES_FILE <br>
                        specify usernames dict file <br>
  -p PASSWORDS_FILE, ––passwords_file=PASSWORDS_FILE <br>
                        specify passwords dict file <br>
  -R, ––recovery        recovery progress <br>
  -P VERIFYTOOL_LISTEN_PORT, ––port=VERIFYTOOL_LISTEN_PORT <br>
                        VerifyTool listen port <br>
  -c CODE_URL, ––code_url=CODE_URL <br>
                        specify verifycode url <br>
  ––https               use https protocol <br>
  ––cookie_url=COOKIE_URL <br>
                        specify get cookies url <br>
  ––error_username=ERROR_USERNAME <br>
                        username does not exist Keyword(regex) <br>
  ––error_password=ERROR_PASSWORD <br>
                        password error keyword(regex) <br>
  ––error_code=ERROR_CODE <br>
                        verifycode Error Keywords(regex)</p>
</code></pre>
<p>example: <br>
<pre><code>python D:/web_login_cracker.py -r req.txt -u u.txt -p p.txt –error_password 密码错误 –error_code 验证码错误  –error_username 帐号不存在 -P 1506 –code_url “http://<strong><em>*.*</em></strong>.cn/servlet/AuthenCodeImage”</p></code></pre>
</li>
<li>done!</li>
</ol>
