<?php
$t_directives = Array(
	"img-src",
	"script-src",
	"style-src",
	"child-src",
	"media-src",
	"font-src",
	"object-src",
	"connect-src"
	);
global $t_directives;

$schemes_not_in_star = Array(
	"data",
	"blob",
	"filesys",
	"il");
global $schemes_not_in_star;

class CSPSourceExpression {
	private $se;

	function __construct($s) {
		$this->se = $s;
	}

	function isHostSource() {
		if (is_object($this->se) && get_class($this->se) == "CSPHostSource") {
			return true;
		} else {
			return false;
		}
	}

	function isStar() {
		if (!is_object($this->se) && ($this->se == "*")) {
			return true;
		} else {
			return false;
		}
	}

	function isScheme() {
		if (!is_object($this->se) && ($this->se != "*")) {
			return true;
		} else {
			return false;
		}
	}

	function getP1() {
		if (is_object($this->se) && get_class($this->se) == "CSPHostSource") {
			return $this->se->getP1();
		} else {
			return $this->se;
		}
	}

	function getP2() {
		if (is_object($this->se) && get_class($this->se) == "CSPHostSource") {
			return $this->se->getP2();
		} else {
			return $this->se;
		}
	}

	function getValue() {
		if (is_object($this->se) && get_class($this->se) == "CSPHostSource") {
			return $this->se->getP1() . "://" . $this->se->getP2();
		} else {
			return $this->se;
		}
	}
}

class CSPHostSource {
	private $sc;
	private $str;

	function __construct($sc,$str) {
		$this->sc = $sc;
		$this->str = $str;
	}

	function getP1() {
		return $this->sc;
	}

	function getP2() {
		return $this->str;
	}
}

class CSPSubject {
	private $sc;
	private $str;

	function __construct($sc,$str) {
		$this->sc = $sc;
		$this->str = $str;
	}

	function getP1() {
		return $this->sc;
	}

	function getP2() {
		return $this->str;
	}	
}

class CSPObject {
	private $sc;
	private $str;

	function __construct($sc,$str) {
		$this->sc = $sc;
		$this->str = $str;
	}

	function getP1() {
		return $this->sc;
	}

	function getP2() {
		return $this->str;
	}	
}

class CSPpolicy {
	// $pol is an array containing all the policies that contribute to the whole policy
	private $pol = Array();
	private $subject;


	function __construct($sc = null, $str = null) {
		if ($sc == null) {
			$this->subject = new CSPSubject("http","example.com");
		} else {
			$this->subject = new CSPSubject($sc,$str);
		}
	}

	function getDownPolicyDirective($directive_name,$p) {
		if (isset($this->pol[$p]['directives'][$directive_name])) {
			return $this->pol[$p]['directives'][$directive_name];
		} else if (isset($this->pol[$p]['directives']['default-src'])) {
			return $this->pol[$p]['directives']['default-src'];
		} else {
			return Array(new CSPSourceExpression("*"));
		}
	}

	function getDownDirective($directive_name) {
		for($p=0;$p<sizeof($this->pol);$p++) {
			if (!isset($composedDirective)) {
				$composedDirective = $this->getDownPolicyDirective($directive_name,$p);
			} else {
				$composedDirective = CSPmeet($composedDirective,$this->getDownPolicyDirective($directive_name,$p));
			}
		}

		return $composedDirective;
	}

	/*
		parseSourceExpression($v)
		$v - a single source expression representing an host, possibly with a scheme
	*/

	function parseSourceExpression($v) {

		if (strpos($v, "://") != 0) {
			list($sc,$str) = explode("://", $v);
			$se  = new CSPHostSource($sc,$str);
		} elseif (substr($v,-1) == ":") {
			/* schemes */
			$se = substr($v, 0, strlen($v) -1 );
		} elseif (strpos($v, "'nonce-") === 0) {
			$sc = "il";
			// forse basta fare così per collassare i nonce
			$str = $v;
			// $str = "nonsha";
			$se  = new CSPHostSource($sc,$str);
		} elseif (strpos($v, "'sha") === 0) {
			$sc = "il";
			$str = $v;
			// $str = "nonsha";
			$se  = new CSPHostSource($sc,$str);
		} elseif ($v == "'unsafe-inline'") {
			$sc = "il";
			$str = "*";
			$se  = new CSPHostSource($sc,$str);
		} elseif ($v == "'unsafe-eval'") {
			// $sc = "il";
			// $str = "eval";
			// $se  = new CSPHostSource($sc,$str);
		} elseif ($v == "strict-dynamic") {
			// $sc = "il";
			// $str = "eval";
			// $se  = new CSPHostSource($sc,$str);
		} elseif ($v == "*") {
			$se = "*";
		} elseif ($v == "'self'") {
			$sc = $this->subject->getP1();
			$str = $this->subject->getP2();
			$se  = new CSPHostSource($sc,$str);
		} else {
			$sc = $this->subject->getP1();
			$str = $v;
			$se  = new CSPHostSource($sc,$str);
		}

		return new CSPSourceExpression($se);
	}

	/*
		policyParse(p)
		$p - a CSP policy header

		TODO: actually does not discriminate between report-only and enforcement

		parse the policy contained in the header $p and adds it to the policies of the current CSPpolicy object
	*/
	function policyParse($p) {
		global $t_directives;
		$policy = Array();

		$directives = explode(";", $p);
		foreach($directives as $dir) {
			$d = explode(" ", ltrim(rtrim($dir)));

			$directive_name	= array_shift($d);

			if ($directive_name != "") {
				if (in_array($directive_name, $t_directives) || $directive_name == "default-src") {
					/* if there are no other directives with the same name already parsed */
					if (!isset($policy['directives'][$directive_name])) {
						$policy['directives'][$directive_name] = Array();
						/* for each source expression */
						foreach ($d as $l) {
							/*
								treat 'none' as slightly different source expression, as it overrides every other possible source per that directive
								and cleans up sources already set, leaving an empty array
							*/
							if ($l == "'none'") {
								$policy['directives'][$directive_name] = Array();
								break;
							} else if ($l != "") {
								$se =  $this->parseSourceExpression($l);
								if ($se->getValue() != null) {
									$policy['directives'][$directive_name][] = $se;
								}
							}
						}
						/* end of source expressions loop */
					/* else we have to apply the meet operator */
					} else {
						$tmp_for_meet = Array();
						/* for each source expression */
						foreach ($d as $l) {
							/*
								treat 'none' as slightly different source expression, as it overrides every other possible source per that directive
								and cleans up sources already set, leaving an empty array
							*/
							if ($l == "'none'") {
								$tmp_for_meet = Array();
								break;
							} else if ($l != "") {
								$se =  $this->parseSourceExpression($l);
								if ($se->getValue() != null) {
									$tmp_for_meet[] = $se;
								}
							}
						}
						/* end of source expressions loop */

						$policy['directives'][$directive_name] = CSPmeet($policy['directives'][$directive_name],$tmp_for_meet);

					}
				} else {
					$policy['directives'][$directive_name] = true;
				}
			}
		}

		$this->pol[] = $policy;
	}
}
?>