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
				current.pieAudits($td.find('.security-fortify-audit-effort'), [parseFloat(measures.TotalRemediationEffortLow, 10), parseFloat(measures.TotalRemediationEffortMedium, 10), parseFloat(measures.TotalRemediationEffortHigh, 10)], ['#3cad1a', '#ad821a', '#d02f2f'],['service:security:fortify:effort-pie-low', 'service:security:fortify:effort-pie-medium', 'service:security:fortify:effort-pie-high']);
			}, 50);

			return current.$super('generateCarousel')(subscription, [
				['id', current.renderKey(subscription)],
				['service:security:fortify:pkey', subscription.data.project.name + ' - ' + subscription.data.project.version],
				['service:security:fortify:vden', measures.VDEN],
				['service:security:fortify:issues', current.$super('icon')('bug', 'service:security:fortify:issues') + Math.ceil(parseFloat((measures.Issues || '0'), 10))],
				['service:security:fortify:audit', current.$super('icon')('stethoscope' + auditedClass,
					Handlebars.compile(current.$messages['service:security:fortify:audit-help-' + auditedKey])([audited, measures.PercentCriticalPriorityIssuesAudited || 0]))
					+ '<span class="security-fortify-progress">' + Handlebars.compile(current.$messages['service:security:fortify:audit-' + auditedKey])(audited)
					+ ' &nbsp; <i class="fas fa-wrench" data-toggle="tooltip" title="' + Handlebars.compile(current.$messages['service:security:fortify:effort-help'])(measures.TotalRemediationEffort) + '"></i></span>'
					+ ' <span class="security-fortify-audit-effort pie"></span>']
			], 1);
		},

		pieAudits: function ($spark, data, colors, messages) {
			current.$super('sparklinePieZoom')($spark, data, {
				sliceColors: colors,
				zoomSize: $spark.closest('.masonry-container').length && '64px',
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
