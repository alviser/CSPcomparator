function addHeader(pol) {
	jQuery(function ($) {
		var headernum = $('#policy_' + pol + '_headers_num').val();
		headernum++;
		var h = $('#policy_' + pol + '_headers > li:first-of-type').clone();

		$('#policy_' + pol + '_headers').append(h);
		$('#policy_' + pol + '_headers > li:last-of-type > h3 > span.header_number').html(headernum);
		$('#policy_' + pol + '_headers > li:last-of-type > textarea').attr("name","policy_" + pol + "_header_" + headernum);
		$('#policy_' + pol + '_headers_num').val(headernum);
	});
}

function delHeader(pol) {
	jQuery(function ($) {
		var headernum = $('#policy_' + pol + '_headers_num').val();
		if (headernum > 1) {
			$('#policy_' + pol + '_headers > li:last-of-type').detach();
			headernum--;
			$('#policy_' + pol + '_headers_num').val(headernum);
		} else {
			alert("you need to have at least one header per policy!");
		}
	});
}