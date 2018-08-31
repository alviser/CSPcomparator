<?php
/*
Plugin Name: CSP policy comparator
Plugin URI: 
Description: Enables the shortcode [csp-compare] to show the csp comparator
Version: 0.1
Author: alvise.rabitti@unive.it, stefano.calzavara@dais.unive.it
Author URI: http://www.unive.it
License: GPL
*/

require_once "CSPclasses.php";
require_once "CSPfunctions.php";

add_shortcode("csp-compare", "show_csp_compare");
wp_register_style("csp-style",plugins_url('style.css',__FILE__ ));
wp_register_script("csp-support",plugins_url('support.js',__FILE__ ));

wp_enqueue_style("csp-style");
wp_enqueue_script("jquery");
wp_enqueue_script("jquery-form");
wp_enqueue_script("csp-support");

function show_csp_compare() {

	ob_start();

	if (!isset($_POST['protocol'])) {
		$_POST['protocol'] = "http";
	}

	if (!isset($_POST['hostname'])) {
		$_POST['hostname'] = "example.com";
	}

	$policy_1 = new CSPpolicy($_POST['protocol'],$_POST['hostname']);
	$policy_2 = new CSPpolicy($_POST['protocol'],$_POST['hostname']);

	$policy_1_num = (isset($_POST['policy_1_headers_num']))?$_POST['policy_1_headers_num']:1;
	$policy_2_num = (isset($_POST['policy_2_headers_num']))?$_POST['policy_2_headers_num']:1;

	for ($p1n=1; $p1n <= $policy_1_num; $p1n++) { 
		$_POST['policy_1_header_' . $p1n] = stripslashes($_POST['policy_1_header_' . $p1n]);
		$policy_1->policyParse($_POST['policy_1_header_' . $p1n]);
	}

	for ($p2n=1; $p2n <= $policy_2_num; $p2n++) {
		$_POST['policy_2_header_' . $p2n] = stripslashes($_POST['policy_2_header_' . $p2n]);
		$policy_2->policyParse($_POST['policy_2_header_' . $p2n]);
	}

	/********************************
		HTML PART
	*********************************/
	?>
	<div class="csp-comparator">
		<form action="#target" method="post">
			<div class="subject_container">
				<h2>Subject</h2>
				<select name="protocol">
					<option value="http" <?php echo ($_POST['protocol'] == "http")?"SELECTED":""; ?>>HTTP</option>
					<option value="https" <?php echo ($_POST['protocol'] == "https")?"SELECTED":""; ?>>HTTPS</option>
				</select>
				<input type="text" name="hostname" value="<?php echo ($_POST['hostname'] != "")?$_POST['hostname']:"example.com"; ?>">
			</div>
			<div class="policy_container">
				<h2>Policy 1</h2>
				<ul id="policy_1_headers">
				<?php
				for ($p1n=1; $p1n <= $policy_1_num; $p1n++) { 
					?>
					<li>
						<h3>header <span class="header_number"><?php echo $p1n; ?></span></h3>
						<textarea name="policy_1_header_<?php echo $p1n; ?>"><?php echo $_POST['policy_1_header_' . $p1n]; ?></textarea>
					</li>
					<?php
				}
				?>
				</ul>
				<input type="hidden" id="policy_1_headers_num" name="policy_1_headers_num" value="<?php echo $policy_1_num; ?>" />
				<div class="clickme" onclick="addHeader('1')">add a header</div>
				<div class="clickme" onclick="delHeader('1')">remove last header</div>
				<?php if ($_SERVER['REMOTE_ADDR'] == '157.138.24.182') { ?>
				<div onclick="jQuery(function($) {$('#p1_dump').slideToggle(); });" class="clickme">show datastructure</div>
				<div id="p1_dump" class="policydump"><?php var_dump($policy_1); ?></div>
				<?php } ?>
			</div>
			<div class="policy_container">
				<h2>Policy 2</h2>
				<ul id="policy_2_headers">
				<?php
				for ($p2n=1; $p2n <= $policy_2_num; $p2n++) { 
					?>
					<li>
						<h3>header <span class="header_number"><?php echo $p2n; ?></span></h3>
						<textarea name="policy_2_header_<?php echo $p2n; ?>"><?php echo $_POST['policy_2_header_' . $p2n]; ?></textarea>
					</li>
					<?php
				}
				?>
				</ul>
				<input type="hidden" id="policy_2_headers_num" name="policy_2_headers_num" value="<?php echo $policy_2_num; ?>" />
				<div class="clickme" onclick="addHeader('2')">add a header</div>
				<div class="clickme" onclick="delHeader('2')">remove last header</div>
				<?php if ($_SERVER['REMOTE_ADDR'] == '157.138.24.182') { ?>
				<div onclick="jQuery(function($) {$('#p2_dump').slideToggle(); });" class="clickme">show datastructure</div>
				<div id="p2_dump" class="policydump"><?php var_dump($policy_2); ?></div>
				<?php } ?>
			</div>
			<div>
				<input type="hidden" name="go" value="1">
				<input type="submit" value="compare" />
			</div>
		</form>
		<div id="target">
			<?php
				if (isset($_POST['go'])) {
					if (isPolicyMoreStrict($policy_1,$policy_2)) {
						if (isPolicyMoreStrict($policy_2,$policy_1)) {
							?>
							<span class='policy equal'>p1</span>
							<span class='sign equal'>=</span>
							<span class='policy equal'>p2</span>
							<br /><?php
						} else {
							?>
							<span class='policy strict'>p1</span>
							<span class='sign strict'>&lt;</span>
							<span class='policy large'>p2</span>
							<br /><?php
						}
					} else {
						if (isPolicyMoreStrict($policy_2,$policy_1)) {
							?>
							<span class='policy large'>p1</span>
							<span class='sign large'>&gt;</span>
							<span class='policy strict'>p2</span>
							<br /><?php
						} else {
							?>
							<span class='policy different'>p1</span>
							<span class='sign different'>&lt;&gt;</span>
							<span class='policy different'>p2</span>
							<br /><?php
						}
					}
					
				}
			?>
		</div>
	</div>
<?php
	$output_string = ob_get_contents();
    ob_end_clean();

	return $output_string;
}