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
		renderDetailsKey: function (subscription) {
			return current.$super('generateCarousel')(subscription, [
				['id', current.renderKey(subscription)],
				['service:security:fortify:pkey', subscription.data.project.name + ' - ' + subscription.data.project.version],
				['service:security:fortify:vden', subscription.data.project.measures.VDEN],
				['service:security:fortify:issues', current.$super('icon')('bug', 'service:security:fortify:issues') + ~~subscription.data.project.measures.Issues]
			], 1);
		},

		/**
		 * Display the Fortify rating : 0...5
		 */
		renderDetailsFeatures: function (subscription) {
			var rating = (subscription.data.project.measures && subscription.data.project.measures.FortifySecurityRating && ~~subscription.data.project.measures.FortifySecurityRating) || 0;
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
