# NetPortDetective
<h3>Description: </h3>
NetPortDetective is a bash script designed to automate host discovery on an internal network, identify their open ports, classify the services and run a thorough scan on discovered web applications.
<h3>Usage: </h3>
<pre> <code>chmod +x NetPortDetective.sh</code></pre>
<pre><code>./NetPortDetective.sh</code>
</pre>
<h3>Details: </h3>
NetPortDetective runs a Host Discovery Scan, identifies open ports and classifies them to 4 classes:
<ul>
  <li>Web Ports</li>
  <li>DataBase Ports</li>
  <li>Mail Ports</li>
  <li>Active Directory Ports</li>
  <li>Other Ports</li>
</ul>

![first](https://github.com/IBarrous/NetPortDetective/assets/126162952/c2ec5648-3694-4fc0-b418-ec244366a192)

![third](https://github.com/IBarrous/NetPortDetective/assets/126162952/8bbd87ff-984d-401e-b8ea-b8fc9c3813f1)

NetPortDetective also identifies the Technologies used to build the discovered web Applications (CMS, FrameWork, Solution) and runs a thorough scan on them.

![second](https://github.com/IBarrous/NetPortDetective/assets/126162952/3964c068-c05d-409c-be85-368cdc65eb0b)

<h3>Note: </h3>
<ul>
 <li>Running NetPortDetective as a root or with sudo is recommended as it might require high privileges to install certain dependencies and run certain scans.</li>
 <li>NetPortDetective works best on Kali Linux since it uses its built in tools (cmseek, nikto, wpscan ...)</li>
</ul>
