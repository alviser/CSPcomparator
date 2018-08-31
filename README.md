# CSPcomparator
This is a PHP implementation of an algorithm able to compare two Content Security Policies and point out if they are equivalent, incomparable, or one is stricter than the other.

A standalone implemetation and a Wordpress plugin are available, you can see and test the plugin at: https://www.dais.unive.it/~csp/csp-comparison-tool/

## Core implementation
The core implementation uses these two files:

* `CSPclasses.php`
* `CSPcomparator.php`

You have to require these in both of the specific implementations

### Standalone implementation
In the `example.php` file you can find a way to directly access the comparator functions.

### Wordpress plugin implementation
You can install the comparator in a Wordpress installation copying this repository in the `wp-content/plugins/` directory.
After activating the plugin you can put the comparator in a page by using the `[csp-compare]` shortcode.