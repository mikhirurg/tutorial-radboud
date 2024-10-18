# Tutorial on Q-SAST tools
This is a tutorial on two query-based SAST (or Q-SAST) tools, namely CodeQL and Semgrep, as part of a guest lecture by NCSC-NL in the Secure Software course at Radboud University. A significant advantage of Q-SAST tools over conventional SAST tools is that the community can contribute to the Q-SAST's capabilities by writing their own rules. This makes it easier to quickly respond to newly discovered vulnerability classes. It also makes Q-SAST tools suitable for information-gathering during penetration tests and code reviews.

## Preliminaries
To properly follow this tutorial you should be able to run CodeQL queries and Semgrep OSS rules on the code included in this repository. There are several ways to do this, which are documented on the respective websites of CodeQL ([here](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli) or [here](https://docs.github.com/en/code-security/codeql-for-vs-code/getting-started-with-codeql-for-vs-code/installing-codeql-for-vs-code)) and Semgrep ([here](https://semgrep.dev/docs/getting-started/quickstart)). I myself run CodeQL using the Visual Studio Code extension, and Semgrep OSS from the command line. Note that it is **not** necessary to create a CodeQL database locally. You can simply import the CodeQL database that is linked to this GitHub repository. 

## The goal
The goal of this tutorial is to write rules for both CodeQL and Semgrep to discover the vulnerabilty [CVE-2022-4223](https://nvd.nist.gov/vuln/detail/CVE-2022-4223) in version 6.16 of the tool pgAdmin 4. The vulnerable code is included in this repository in the folder `pgAdmin4-REL-6_16`. For more information about pgAdmin 4 and this vulnerability, see [here](https://frycos.github.io/vulns4free/2022/12/02/rce-in-20-minutes.html). If you are really adventurous, and would like to try out running a vulnerable version of this software, go [here](https://github.com/vulhub/vulhub/tree/master/pgadmin/CVE-2022-4223).

Note that the default versions of both CodeQL and Semgrep OSS already include rules that detect this vulnerability. Nevertheless, it is a worthwile exercise to write your own rules, because you will obtain:

- A better understanding of how these Q-SAST tools work and how they compare to each other. 
- A more in-depth understanding of the vulnerability at hand. This is particularly interesting because the vulnerability is similar to the vulnerabilities in Ivanti ([this one](https://nvd.nist.gov/vuln/detail/CVE-2023-46805) combined with [this one](https://nvd.nist.gov/vuln/detail/CVE-2024-21887)) discussed during the lecture.
- Some feeling for how you can use these tools for pentesting and code review. 

Recall that the vulnerability we are researching arises because untrusted user data finds its way to a possible vulnerable function. This untrusted user data is called the *source*, and the vulnerable function is called the *sink*. A nice feature of Semgrep is that, if we specify the source and the sink, Semgrep can automatically search for a possible path between them. 

### Part 1.1: Finding the source 
pgAdmin 4 exposes itself to the internet by using the Python web framework [Flask](https://flask.palletsprojects.com/en/3.0.x/). In this framework, user data is accessed through the object `request`. 

> **Exercise 1**. Write a Semgrep rule that finds all usages of the word `request`. 
> <details>
>  <summary>Hint 1</summary>
>  You could use the following template
>
>  ```yaml
>  rules:
> - id: request-usages
>  languages:
>    - python
>  message: The word 'request' occurs here.
>  pattern: 
>  severity: INFO
>  ```
>  What to put after `pattern:`?
> </details>
> <details>
>  <summary>Hint 2</summary>
> You should get 766 findings.
> </details> 

Note that line 266 of the file `web/pgadmin/browser/utils.py` contains the following code:
```python
http_method = flask.request.method.lower()
```
However, simply searching for the pattern `request` does not match this line. 
> **Exercise 2**. Write a Semgrep rule that finds all usages of the object `flask.request`.
> <details>
> <summary>Hint 1</summary>
> You should get 775 findings.
> </details> 

Notice how you get more findings than before? This is because semgrep takes the semantics of the code into account. It therefore knows that if a file contains
```python
from flask import request
```
then every usage of `request` is in fact one of `flask.request`.

Since some attributes of `flask.request` are more likely to contain untrusted user-input, it might be useful to keep track of the specific attribute that our rule matches. 
> **Exercise 3**. Write a Semgrep rule that finds and displays all usages of attributes of the object `flask.request`.
> <details>
> <summary>Hint 1</summary>
> Use a metavariable.
> </details> 
> <details>
> <summary>Hint 2</summary>
> You could use the following template
>
> ```yaml
> rules:
> - id: flask-request-attributes
>   languages:
>     - python
>   message: The attribute '$ATTRIBUTE' of the object 'flask.request' is used here.
>   pattern: 
>   severity: INFO
> ```
>  What to put after `pattern:`?
> </details>
> <details>
> <summary>Hint 3</summary>
> You should get 762 findings.
> </details> 

### Part 1.2: Finding the sink 
The sink of our vulnerability is the module `subprocess`, which is used to spawn new processes.
> **Exercise 4**. Write a Semgrep rule that finds and displays calls to *methods* of the module `subprocess`.
> <details>
> <summary>Hint 1</summary>
> Again use a metavariable, but now also use ellipses (...). 
> </details> 
> <details>
> <summary>Hint 2</summary>
> You could use the following template
>
> ```yaml
> rules:
> - id: subprocess-method-calls
>   languages:
>     - python
>   message: The method '$METHOD' of the module 'subprocess' is used here.
>   pattern: 
>   severity: INFO
> ```
>  What to put after `pattern:`?
> </details>
> <details>
> <summary>Hint 3</summary>
> You should get 16 findings.
> </details> 

### Part 1.3: Taint tracking from source to sink
It's now time to make the connection from source to sink. 
> **Exercise 5**. Write a Semgrep rule that uses taint mode to detect the flow of untrusted data from `flask.request` into a `subprocess` method call. 
> <details>
> <summary>Hint 1</summary>
> You could use the following template
>
>```yaml
> rules:
> - id: request-subprocess-taint-tracking
>  languages:
>    - python
>  message: Untrusted user-input flows from 'flask.request.$ATTRIBUTE' into a call to 'subprocess.$METHOD'.
>  mode: taint
>  pattern-sources:
>    - pattern: 
>  pattern-sinks:
>    - pattern: 
>  severity: WARNING
> ```
>  What to put after each `pattern:`?
> </details>

Running this final rule should result in precisely 1 match. You can use the command-line flag ``--dataflow-traces`` to track how the data flows from the source to the sink. On my machine, this gives the following output:
```
pgadmin4-REL-6_16/web/pgadmin/misc/__init__.py
    ❯❱ semgrep-rules.request-subprocess-taint-tracking
          Untrusted user-input flows from 'flask.request.data' into a
          call to 'subprocess.getoutput'.                            
                                                                     
          224┆ subprocess.getoutput('"{0}"  
               --version'.format(full_path))
    
    
          Taint comes from:
    
          205┆ data = request.data.decode('utf-8')
    
    
          Taint flows through these intermediate variables:
    
          205┆ data = request.data.decode('utf-8')
    
          213┆ binary_path =                            
               replace_binary_path(data['utility_path'])
    
          216┆ full_path = os.path.abspath(
    
    
                This is how taint reaches the sink:
    
          224┆ subprocess.getoutput('"{0}"  
               --version'.format(full_path))
```
If you get something similar: well done! The rule we've now developed works in this particular case and demonstrates some of the key features of Semgrep. It is, however, still far from refined and may give many false-positives in practice. For a more robust solution, I recommend you to check out [the corresponding rule in the official Semgrep rule database](https://github.com/semgrep/semgrep-rules/blob/develop/python/flask/security/injection/subprocess-injection.yaml). 

## Part 2: writing your own CodeQL query

We will now repeat the same process, but then to construct a CodeQL query. As you will see, this can be a bit trickier than writing a Semgrep rule. Also - at least on my machine - running a CodeQL query takes more time, which slows down the testing process. However, CodeQL as a programming language has more features, and the reuslts are often more accurate.

### Part 2.1: Finding the source 
Recall from Part 1 that we need to find accesses of attributes of the `flask.request` object. There is a CodeQL module, called [API graphs](https://codeql.github.com/docs/codeql-language-guides/using-api-graphs-in-python/), designed specifically for such external library accesses. While this module is useful in practice, we will for educational purposes direcly write a query that does not depend on it.
> **Exercise 6**. Write a CodeQL query that finds all instances where an attribute of an object named `request` is accessed.
> <details>
>  <summary>Hint 1</summary>
>  You could use the following template
>
>```javascript
> /**
> * @id flask-request-attribute-acccess
> * @severity error
> * @kind problem
> */
>
> import python
>
> from Attribute a 
> where 
> select a, "request." + a.getAttr()
> ```
>  What to put after `where`?
> </details>
> <details>
>  <summary>Hint 2</summary>
> You should get 754 results.
> </details> 

Let's use CodeQL's object-oriented features and create a class. 

> **Exercise 7**. Create a CodeQL class that contains all findings from the previous exercise.
> <details>
>  <summary>Hint 1</summary>
>  You could use the following template
>
>```javascript
> /**
> * @id flask-request-attribute-acccess
> * @severity error
> * @kind problem
> */
>
> import python
>
> class RequestAttribute extends Attribute {
>     RequestAttribute() {
>        
>     }
>  }
> 
>  from RequestAttribute ra
>  select ra, "request." + ra.getAttr()
> ```
>  What to put in the body of the class constructor?
> </details>

### Part 2.2: Finding the sink 
> **Exercise 8**. Write a CodeQL query that finds all instances where an attribute of an object named `subprocess` is accessed.
> <details>
>  <summary>Hint 1</summary>
>  Compare to Exercise 6.
> </details> 
> <details>
>  <summary>Hint 2</summary>
> You should get 14 results.
> </details> 
This query also finds fields, like `subprocess.PIPE`, whereas we are only interested in function calls. For this we can use the `Call` class. 
> **Exercise 9**. Create a CodeQL predicate that selects amongst all expressions of type `Call` those that are calls to functions of the subprocess module. 
> <details>
>  <summary>Hint 1</summary>
>  Use CodeQL's `exist` quantifier.
> </details> 
> <details>
>  <summary>Hint 2</summary>
>  You could use the following template
>
>```javascript
> /**
> * @id subprocess-call-predicate
> * @severity error
> * @kind problem
> */
>
> import python
>
> predicate isSubprocessCall(Call c) {
>   
> }
>
> from Call c where
> isSubprocessCall(c)
> select c, "subprocess call"
> ```
>  What to put in the body of the predicate?
> </details>
> <details>
>  <summary>Hint 3</summary>
> You should get 9 findings.
> </details> 

### Part 2.3: Taint tracking from source to sink
> **Exercise 10**. Write a CodeQL query that detects the flow of untrusted data from  a `request` attribute into a `subprocess` method call. 
> <details>
> <summary>Hint 1</summary>
> You could use the following template
>
>```javascript
> /**
> * @kind path-problem
> * @problem.severity error
> * @id taint-tracking-request-subprocess
> */
>
> import python
> import semmle.python.dataflow.new.DataFlow
> import semmle.python.dataflow.new.TaintTracking
> import semmle.python.ApiGraphs
> import semmle.python.dataflow.new.RemoteFlowSources
> import MyFlow::PathGraph
>
>
> private module MyConfig implements DataFlow::ConfigSig {
>   predicate isSource(DataFlow::Node source) {
>     
>   }
>
>   predicate isSink(DataFlow::Node sink) {
>    
>   }
> }
>
> module MyFlow = TaintTracking::Global<MyConfig>; 
>
> from MyFlow::PathNode source, MyFlow::PathNode sink
> where MyFlow::flowPath(source, sink)
> select sink.getNode(), source, sink, "subprocess sink called with untrusted data from request"
> ```
>  What to put in each predicate body?
> </details>
> <details>
>  <summary>Hint 2</summary>
> Use the `.asExpr()` method of the `DataFlow::Node` class. 
> </details> 
Again, our query works perfectly for our target pgAdmin 4, but is generally not as accurate as the [official CodeQL query](https://github.com/github/codeql/blob/main/python/ql/src/Security/CWE-078/CommandInjection.ql) for this vulnerability. 

## Conclusion and further reading

I hoped you enjoyed this tutorial! For questions, feel free to reach out to myfirstname.mylastname@ncsc.nl. Here are some resources that might be interesting for further reading:
- Technical information about the vulnerability in Ivanti (technical): https://www.assetnote.io/resources/research/high-signal-detection-and-exploitation-of-ivantis-pulse-connect-secure-auth-bypass-rce
- Also about the vulnerability in Ivanti, but from a more threat analytical perspective: https://cloud.google.com/blog/topics/threat-intelligence/suspected-apt-targets-ivanti-zero-day/
- Using CodeQL for offensive security: https://www.youtube.com/watch%3Fv%3D-bJ2Ioi7Icg&ved=2ahUKEwiAlMWEkpiJAxWq1QIHHbfrN3EQwqsBegQICxAF&usg=AOvVaw06tjK7XsK8vv_fbOMLsXnj
- An empirical study on the effectiveness of query-based SAST-tools (paywalled): https://ieeexplore.ieee.org/document/10400834