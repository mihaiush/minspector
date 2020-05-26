# minspector
Scriptable milter.

Emails are analyzed using user python scripts. Based on https://pythonhosted.org/milter/.

## Usage
```python
import Milter
from minspector import MInspector, Test, LOG

LOG.enable_timestamp()
#LOG.enable_debug()

# Log only test
class test(Test):
    def main(self, email):
        return True
test('0000', 'NEW-MESSAGE')

Milter.factory = MInspector
milter = 'MINSPECTOR'
LOG.info('Starting {}'.format(milter))
Milter.runmilter(milter, '/run/minspector/sock')
```
The `MInspector` milter puts the email in a standard format and executes a series of tests defined by writing python code. 

## Writing tests
A test is created by defining a class which inherits the `minspector.Test` class and by instantiating this class:
```python
class test(Test):
...
test('0000', 'NEW-MESSAGE')
```
The `Test` class has 2 methods:
- `main(self, email)`
- `line(self, email, text_line)`

The milter will execute first the `main` method of each test and after that for each text line in the email the `line` method of each test. The parameters passed to the `main` and `line` methods are:
- `email`, the milter itself (https://pythonhosted.org/pymilter/classMilter_1_1Base.html) enhanced with some extra attributes: 
  - `.id`, unique id to identify the message in log
  - `.client.ip`, client ip
  - `.client.port`, client port
  - `.client.name`, client hostname
  - `.helo`, hello message
  - `.mail_from`, sender
  - `.rcpt_to`, array of recipients
  - `.headers`, `.headers_raw`, if `headers_raw` is `False`, `headers` is a dictionary of lowercase headers. If `headers_raw` is `True` an error has occurred during headers processing and `headers` is a list of tuples as received by milter.
  - `.text`, an array containing the text lines from the body preamble and all the parts of the body with content type `text/*`
- `text_line`, only for `line` method, is the current line of `email.text`

Each method must return `True` for a positive test and `False` for a negative one. `main` should be used for initialization and for tests which don't require the body of the message (decision is based on headers and protocol data) and `line` should be used for tests requiring the body. However as the `email.text` attribute is also present in `main` it is possible to analyze the text here and don't use `line` at all.

What happens when a test is positive is decided by the way the test was instantiated. The constructor of `Test` class has the following parameters:
- `label`, a text label which will identify the test in log and it can be used in the message sent back by the SMTP server to the client,
- `policy`, it can be:
  - `ACCEPT`, message is accepted, processing stops
  - `REJECT`, message is permanently rejected, processing stops
  - `DEFER`, message is temporary rejected, processing stops
  - `DISCARD`, message is silently discarded, processing stops
  - anything else is log-only, processing continues
- `message`, is the template for the response send by the SMTP server to client. Default is `MI-{id}-{label}-{stage}`. The parameters which can be use in template are:
  - `label`, test label
  - `id`, the message id
  - `stage`, `M` for `main` and `L` for `line`


 
