<?php
require_once "CSPclasses.php";
require_once "CSPfunctions.php";

$policy_1 = new CSPpolicy($protocol,$hostname);
$policy_2 = new CSPpolicy($protocol,$hostname);

$policy_1->policyParse($policy_1);
$policy_2->policyParse($policy_2);

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