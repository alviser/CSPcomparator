<?php
/*
	this is an example toy starting point to test the CSP comparator
	without using it throught the Wordpress plugin
*/

require_once "CSPclasses.php";
require_once "CSPfunctions.php";

$protocol = "http";
$hostname = "example.com";

$policy_source_1 = "default-src none;";
$policy_source_2 = "default-src *;";

$policy_1 = new CSPpolicy($protocol,$hostname);
$policy_2 = new CSPpolicy($protocol,$hostname);

$policy_1->policyParse($policy_source_1);
$policy_2->policyParse($policy_source_2);

if (isPolicyMoreStrict($policy_1,$policy_2)) {
	if (isPolicyMoreStrict($policy_2,$policy_1)) {
		?>
		p1 = p2
		<?php
	} else {
		?>
		p1 < p2
		<?php
	}
} else {
	if (isPolicyMoreStrict($policy_2,$policy_1)) {
		?>
		p1 > p2
		<?php
	} else {
		?>
		cannot compare p1 and p2
		<?php
	}
}
?>