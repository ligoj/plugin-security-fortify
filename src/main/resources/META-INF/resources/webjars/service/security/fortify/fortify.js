define(function () {
	var current = {

		configureSubscriptionParameters: function (configuration) {
			current.$super('registerXServiceSelect2')(configuration, 'service:security:fortify:pkey', 'service/security/fortify/', null, false, current.loadFortifyProjectVersions);
			current.registerFortifyProjectVersion(configuration, 'service:security:fortify:version');
		},

		/**
		 * Render Fortify key.
		 */
		renderKey: function (subscription) {
			return current.$super('renderKey')(subscription, 'service:security:fortify:version');
		},

		/**
		 * Render Fortify home page.
		 */
		renderFeatures: function (subscription) {
			// Add Project group link
			var url = subscription.parameters['service:security:fortify:url'] + '/flex/index.jsp' + (subscription.parameters['service:security:fortify:version'] ? '#projectVersionId=' + subscription.parameters['service:security:fortify:version'] : '');
			var result = current.$super('renderServicelink')('home', url, 'service:security', null, ' target="_blank"');
			// Help
			result += current.$super('renderServiceHelpLink')(subscription.parameters, 'service:security:help');
			return result;
		},

		/**
		 * Render Sonar details : id, name and pkey.
		 */
		renderDetailsKey: function (subscription, $td) {
			var measures = subscription.data.project.measures;
			var audited = parseFloat(measures.PercentAudited || 0, 10);
			var auditedClass = '';
			var inProgress = true;
			var auditedKey = 'in-progress';
			if (audited === 100) {
				auditedClass = ' text-success';
				auditedKey = 'complete';
				inProgress = false;
			} else if (audited >= 90) {
				auditedClass = ' faa-flash animated text-primary';
			} else if (audited >= 80) {
				auditedClass = ' faa-flash animated text-warning';
			} else if (audited > 0) {
				// Audit in progress
				auditedClass = ' text-danger';
				auditedKey = 'new';
				inProgress = false;
			}

			window.setTimeout(function () {
				if (inProgress) {
					current.pieAudits([parseFloat(audited, 10), 100 - parseFloat(audited, 10)], subscription, $td.find('.security-fortify-audit-progress'), ['#000000', '#FFFFFF'],['service:security:fortify:audit-pie-audited', 'service:security:fortify:audit-pie-not-audited']);
				}
				current.pieAudits([parseFloat(measures.TotalRemediationEffortLow, 10), parseFloat(measures.TotalRemediationEffortMedium, 10), parseFloat(measures.TotalRemediationEffortHigh, 10)], subscription, $td.find('.security-fortify-audit-effort'), ['#1666ad', '#bfca24', '#d02f2f'],['service:security:fortify:effort-pie-low', 'service:security:fortify:effort-pie-medium', 'service:security:fortify:effort-pie-high']);
			}, 50);

			return current.$super('generateCarousel')(subscription, [
				['id', current.renderKey(subscription)],
				['service:security:fortify:pkey', subscription.data.project.name + ' - ' + subscription.data.project.version],
				['service:security:fortify:vden', measures.VDEN],
				['service:security:fortify:issues', current.$super('icon')('bug', 'service:security:fortify:issues') + Math.ceil(parseFloat((measures.Issues || '0'), 10))],
				['service:security:fortify:audit', current.$super('icon')('stethoscope' + auditedClass,
					Handlebars.compile(current.$messages['service:security:fortify:audit-help-' + auditedKey])([audited, measures.PercentCriticalPriorityIssuesAudited || 0]))
					+ Handlebars.compile(current.$messages['service:security:fortify:audit-' + auditedKey])(audited)
					+ (inProgress ? ' <span class="security-fortify-audit-progress pie"></span>' : '')
					+ ' &nbsp; <i class="fas fa-wrench" data-toggle="tooltip" title="' + Handlebars.compile(current.$messages['service:security:fortify:effort-help'])(measures.TotalRemediationEffort) + '"></i> '
					+ Handlebars.compile(current.$messages['service:security:fortify:effort'])(measures.TotalRemediationEffort)
					+ ' <span class="security-fortify-audit-effort pie"></span>']
			], 1);
		},

		pieAudits: function (data, subscription, $spark, colors, messages) {
			require(['sparkline'], function () {
				current.setupSparkline(data, $spark, colors, messages, '20px');

				// Zoom and auto update tooltips
				$spark.on('mouseenter', function (e) {
					if (!$spark.is('.zoomed')) {
						$spark.addClass('zoomed');
						current.setupSparkline(data, $spark, colors, messages, '128px');
						window.setTimeout(function () {
							$spark.addClass('zoomed2');
							$spark.find('canvas').on('mouseleave', function (e2) {
								$spark.removeClass('zoomed');
								current.setupSparkline(data, $spark, colors, messages, '20px');
								window.setTimeout(function () {
									$spark.removeClass('zoomed2');
								}, 50);
							})
						}, 50);
					}
				});
			});
		},

		setupSparkline: function (data, $spark, colors, messages, size) {
			$spark.find('canvas').remove();
			$spark.sparkline(data, {
				type: 'pie',
				sliceColors: colors,
				width: size,
				height: size,
				fillColor: 'black',
				borderWidth: size === "128px" ? 4 : 2,
				borderColor: '#ffffff',
				tooltipFormatter: function (sparkline, options, fields) {
					return Handlebars.compile(current.$messages[messages[fields.offset]])([current.$super('roundPercent')(fields.percent), fields.value, sparkline.total]);
				}
			});
		},

		/**
		 * Display the Fortify rating : 1...5
		 */
		renderDetailsFeatures: function (subscription) {
			var measures = subscription.data.project.measures;
			var rating = measures && measures.FortifySecurityRating || 0;
			var color = rating && ['default', 'danger', 'warning', 'warning', 'primary', 'success'][rating];
			return color ? '<span data-toggle="tooltip" title="' + current.$messages['service:security:fortify:rating'] + '" class="label label-' + color + '">' + rating + '</span>' : '';
		},

		/**
		 * Register Fortify Version id select2
		 */
		registerFortifyProjectVersion: function (configuration, id) {
			var cProviders = configuration.providers['form-group'];
			var previousProvider = cProviders[id] || cProviders.standard;
			cProviders[id] = function (parameter, container, $input) {
				// Render the normal input
				previousProvider(parameter, container, $input);
				_(id).select2({
					data: []
				});
				_(id).select2('readonly', true);
			};
		},

		/**
		 * load fortify version id
		 */
		loadFortifyProjectVersions: function () {
			$.ajax({
				dataType: 'json',
				url: REST_PATH + 'service/security/fortify/versions/' + current.$super('getSelectedNode')() + '/' + _('service:security:fortify:pkey').val() + '/',
				type: 'GET',
				success: function (data) {
					var version = _('service:security:fortify:version');
					version.select2({
						data: (data.length === 0) ? [] : {
							results: data,
							text: 'name'
						}
					});
					if (data.length === 1) {
						version.select2('val', data[0].id);
					}
					version.select2('readonly', data.length <= 1);
				}
			});
		}
	};
	return current;
});
