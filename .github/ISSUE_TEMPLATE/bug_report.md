---
name: Bug report
labels: 'bug report'
about: Report a bug in libfido2

---

<!-- Please use the questions below as a template. Thank you! -->

**What version of libfido2 are you using?**

**What operating system are you running?**

**What application are you using in conjunction with libfido2?**

**How does the problem manifest itself?**

**Is the problem reproducible?**

**What are the steps that lead to the problem?**

**Does the problem happen with different authenticators?**

**Please include the output of `fido2-token -L`.**

<details>
<summary><code>fido2-token -L</code></summary>
<br>
<pre>
$ fido2-token -L
<br>
fido2-token is provided by the fido2-tools package on Debian and Ubuntu.

</pre>
</details>

**Please include the output of `FIDO_DEBUG=1`.**

<details>
<summary><code>FIDO_DEBUG=1</code></summary>
<br>
<pre>
$ FIDO_DEBUG=1 &lt;command&gt;

</pre>
</details>
