<?php
/* CSPmeet($v1,$v2)
 *
 * implements the meet algorithm
 * expects two arrays of CSPSourceExpression objects
 * returns an array of CSPSourceExpression objects containing the result of the meet algorithm
 * as described in section 2.2, definition 9
 */

function CSPmeet($v1,$v2) {
	$meet = Array();

	foreach ($v1 as $value) {
		foreach ($v2 as $check) {
			if (isValueMoreStrict($value,$check) && (!in_array($value, $meet))) {
				$meet[] = $value;
			}
		}
	}

	foreach ($v2 as $value) {
		foreach ($v1 as $check) {
			if (isValueMoreStrict($value,$check) && (!in_array($value, $meet))) {
				$meet[] = $value;
			}
		}
	}

	return $meet;
}

/* CSPsmartLookup($directive_name,$policy,[$policy2]) {
 *
 * returns an array of CSPSourceExpression objects which is the $directive_name one if it exists in $policy
 * elseway it falls back on default-src one
 * elseway it falls on an empty one
 *
 * if a second policy is given it returns the result of CSPmeeting the directive on the two policies
 */

function CSPsmartLookup($directive_name,$policy1,$policy2 = null) {

	if ($policy2 == null) {
		if ($policy1->getDownDirective($directive_name) != -1) {
			return $policy1->getDownDirective($directive_name);
		} else {
			return Array();
		}
	} else {
		return CSPmeet(CSPsmartLookup($directive_name,$policy1),CSPsmartLookup($directive_name,$policy_2));
	}
}


/*
	values / directives / policy checking
*/

function isValueMoreStrict($v1,$v2) {
	global $schemes_not_in_star;

	/* check reflexivity */
	if ($v1->getValue() == $v2->getValue()) {
		// echo "true on reflexivity<br />";
		return true;
	}

	/* def 7, rule 1 */
	if (($v1->isScheme()) &&
		($v2->isStar()) &&
		(!in_array($v1->getValue(),$schemes_not_in_star))) {
			// echo "true on rule 1<br />";
			return true;
	}

	/* def 7, rule 2 */
	if (($v1->isHostSource()) && 
		($v2->isStar()) &&
		(!in_array($v1->getP1(),$schemes_not_in_star))) {
			// echo "true on rule 2<br />";
			return true;
	}

	/* def 7, rule 3 TODO: check this*/
	if (($v1->isScheme()) && 
		($v1->getValue() == $v2->getP1()) &&
		($v2->getP2() == "*")) {
			// echo "true on rule 3<br />";
			return true;
	}

	/* def 7, rule 4 */
	if (($v1->isHostSource()) &&
		($v2->isScheme()) && 
		($v1->getP1() == $v2->getValue())) {
			// echo "true on rule 4<br />";
			return true;
	}

	/* def 7, rules 5-6 */
	if (($v1->isHostSource()) &&
		($v2->isHostSource()) && 
		($v1->getP1() == $v2->getP1()) &&
		($v2->getP2() == "*")) {
			// echo "true on rule 5-6<br />";
			return true;
	}

	/* def 7, rule 7 */ 
	if ($v1->isHostSource() &&
		$v2->isHostSource() &&
		$v1->getP1() == $v2->getP1()) {
		$h1 = explode(".", $v1->getP2());
		$h2 = explode(".", $v2->getP2());

		$h1 = array_reverse($h1);
		$h2 = array_reverse($h2);

		// echo "arrays reversed<br />";
		$i = 0;
		while($h1[$i] == $h2[$i]) {
			$i++;
		}


		if ($h2[$i] == "*") {
			// echo "true on rule 7<br />";
			return true;
		}
	}

	/* def 7, rule 8 */
	if (($v1->getP1() == "il") && 
		($v2->getP1() == "il") &&
		($v2->getP2() == "*")) {
			// echo "true on rule 8<br />";
			return true;
	}


	return false;
}

function isDirectiveMoreStrict($dname,$p1,$p2) {
	

	$d1 = CSPsmartLookup($dname,$p1);
	if (sizeof($d1) == 0) {
		/* handler for the cases where the set is empty -> 'none' or similar */
		// echo "checking p1." . $dname . ": empty/none is always equal or more strict<br />";
		return true;
	} else {
		foreach ($d1 as $vd1) {
			$isStrict = false;
			$d2 = CSPsmartLookup($dname,$p2);
			// echo "checking p1." . $dname . "." . $vd1->getValue() . ":<br />";
			foreach ($d2 as $vd2) {
				// echo "--> against p2 value of: " . $vd2->getValue() . "<br />";
				if (isValueMoreStrict($vd1,$vd2)) {
					$isStrict = true;
					break;
				}
			}
		
			if (!$isStrict) {
				return false;
			}
		}
	}

	return true;
}

/*
	isPolicyMoreStrict(policy1,policy2)

	checks if policy1 <= policy2

*/

function isPolicyMoreStrict($p1,$p2) {
	global $t_directives;

	foreach($t_directives as $d_name) {
		if (!isDirectiveMoreStrict($d_name,$p1,$p2)) {
			return false;
		}
	}

	return true;
}
?>