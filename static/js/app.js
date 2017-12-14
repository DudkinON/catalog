(function () {
  // define url api
  var HOST = '/api';

  // Url constructor
  var uri = function (url) {
    return HOST + url;
  };

  // define app
  var app = angular.module('app', [
    'ngResource',
    'angularFileUpload',
    'base64'
  ]);

  var isEmail = function (email) {
    /**
     * Email validation
     * @param string (email)
     * @type {RegExp}
     * @return bool
     */
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
  };


  // define app config
  app.config(['$locationProvider', '$resourceProvider', '$interpolateProvider',
    function ($locationProvider, $resourceProvider, $interpolateProvider) {
      $interpolateProvider.startSymbol('{a');
      $interpolateProvider.endSymbol('a}');
      $locationProvider.html5Mode(true);
      $resourceProvider.defaults.stripTrailingSlashes = false;
    }]);


  // // TODO: auth
  // app.factory('auth', ['$base64', '$http', function ($base64, $http) {
  //   return {
  //     query: function (url, token, success) {
  //       var credentials = '';
  //       if (token.indexOf(':') > -1) {
  //         credentials = $base64.encode(token)
  //       } else {
  //         credentials = $base64.encode(token + ':');
  //       }
  //
  //       return $http({
  //         method: 'GET',
  //         url: url,
  //         headers: {'Authorization': 'Basic ' + credentials}
  //       }).then(success);
  //     }
  //   }
  // }]);
  //
  // // TODO: authPOST
  // app.factory('authPOST', ['$base64', '$http', function ($base64, $http) {
  //   return {
  //     query: function (url, data, token, success) {
  //       var credentials = $base64.encode(token + ':');
  //       return $http({
  //         method: 'POST',
  //         url: url,
  //         data: data,
  //         headers: {'Authorization': 'Basic ' + credentials}
  //       }).then(success);
  //     }
  //   }
  // }]);

  // TODO: run app
  app.run(function ($rootScope, $resource, $templateCache) {
  });

  // TODO: init facebook api
  window.fbAsyncInit = function () {

    FB.init({
      appId: document.getElementById('facebook-app-id').getAttribute('data-app-id'),
      status: true,
      autoLogAppEvents: true,
      cookie: true,
      xfbml: true,
      scope: 'publc_profile, email',
      version: 'v2.11'
    });
  };

  // TODO: upload Facebook SDK
  (function (d, s, id) {
    var js, fjs = d.getElementsByTagName(s)[0];
    if (d.getElementById(id)) {
      return;
    }
    js = d.createElement(s);
    js.id = id;
    js.src = "https://connect.facebook.net/en_US/sdk.js";
    fjs.parentNode.insertBefore(js, fjs);
  }(document, 'script', 'facebook-jssdk'));

  // TODO: upload Google client
  (function (d, s, id) {
    var js, fjs = d.getElementsByTagName(s)[0];
    if (d.getElementById(id)) {
      return;
    }
    js = d.createElement(s);
    js.id = id;
    js.src = "https://apis.google.com/js/client.js?onload=onLoadFunction";
    js.async = true;
    fjs.parentNode.insertBefore(js, fjs);
  }(document, 'script', 'google-sign-in-script'));

  // TODO: function onLoadFunction
  function onLoadFunction() {
    gapi.client.setApiKey(document.getElementById('google-app-id').getAttribute('data-key-api'));
    gapi.client.load('plus', 'v1', function () {
    })
  }

  // TODO: Login controller
  app.controller('LoginController', function ($resource, $scope, $http, $window) {

    this.FBLogin = function () {
      toggle();
      FB.login(function (response) {
        if (response.authResponse) {
          var access_token = FB.getAuthResponse()['accessToken'];
          FB.api('/me', function (response) {
            var POST = $resource(uri('/oauth/facebook'));
            var json = new POST();
            json.data = {"access_token": access_token};

            POST.save(json, function (data) {
              if (data.error) {
                toggle();
                console.log(data.error);
              }else if (data) {
                toggle();
                console.log(data);
                $window.location.href = '/profile';
              }
            }, function (data) {
              var message = 'Server error, try it later';
              console.log(message);
              toggle();
              if (data.error) {
                console.log(data.error);
              }
            });
          });
        } else {
          console.log('User cancelled login or did not fully authorize.');
        }
      });
    };

    this.GoogleLogin = function () {
      var googleMeta = document.getElementById('google-app-id');
      toggle();
      var params = {
        'clientid': googleMeta.getAttribute('data-clientid'),
        'cookiepolicy': googleMeta.getAttribute('data-cookiepolicy'),
        'redirecturi': googleMeta.getAttribute('data-redirecturi'),
        'accesstype': googleMeta.getAttribute('data-accesstype'),
        'approvalprompt': googleMeta.getAttribute('data-approvalprompt'),
        'scope': googleMeta.getAttribute('data-scope'),
        'callback': function (result) {
          if (result['status']['signed_in']) {
            $http({
                method: 'POST',
                url: uri('/oauth/google'),
                data: result.code,
                headers: {
                  'Content-Type': 'application/octet-stream; charset=utf-8'
                }
              }
            ).then(function (result) {
              toggle();
              console.log(result);
              $window.location.href = '/profile';
            }, function (error) {
              console.log(error);
            });

          }
        }
      };
      gapi.auth.signIn(params);
    };

    var toggle = function () {
      /**
       * toggle buttons and loading line
       */
      $('#buttons').toggle();
      $('#p2').toggle();
    };
  });

  // TODO: Picture controller

  app.controller('PictureController', function (FileUploader, $base64) {
    var $scope = this;
    $scope.addedPhoto = false;
    $scope.user = {};
    $scope.user.uid = $('#uid').val();
    $scope.user.token = $('#token').val();
    $scope.user.picture = $('#user-picture').val();
    var credentials = $base64.encode($scope.user.token + ':');
    var uploader = $scope.uploader = new FileUploader({
      method: 'POST',
      url: uri('/profile/edit/photo/' + $scope.user.uid),
      headers: {'Authorization': 'Basic ' + credentials},
      autoUpload: true
    });

    // filters
    uploader.filters.push({
      name: 'imageFilter',
      fn: function (item /*{File|FileLikeObject}*/, options) {
        var type = '|' + item.type.slice(item.type.lastIndexOf('/') + 1) + '|';
        return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
      }
    });

    uploader.onWhenAddingFileFailed = function (item /*{File|FileLikeObject}*/, filter, options) {
      $scope.addedPhoto = false;
      console.log("Error file format");
    };
    uploader.onAfterAddingFile = function (fileItem) {
      $scope.addedPhoto = true;
    };
    uploader.onSuccessItem = function (fileItem, response, status, headers) {
      if (response.error) {
        console.log(response.error);
      } else {
        $scope.user.picture = response.picture;
        $scope.addedPhoto = false;
      }
    };
    uploader.onErrorItem = function (fileItem, response, status, headers) {
      console.log("Error upload a photo");
    };
  });

  // TODO: Image controller
  app.controller('ImageController', function ($resource, $base64, FileUploader) {
    var $scope = this;
    var $rootScope = angular.element(document.querySelector('[ng-app="app"]')).scope();

    // Define scope
    $scope.error = false;
    $scope.user = {};
    $scope.addedPhoto = false;
    $scope.itemId = $('#car-id').val();

    $resource(uri('/car/' + Number($scope.itemId))).get(function (res) {
      $scope.car = res;
      if ($scope.car.images === undefined || !$scope.car.images.length) $scope.currentImg = {};
      else $scope.currentImg = $scope.car.images[0];
    });

    $scope.chooseImg = function (image) {
      $('#main-image').attr("src", image.url);
      $scope.currentImg = image;
    };

    var toggle = function () {
      /**
       * toggle forms add car and add images
       */
      $('#add-car').toggle();
      $('#add-item-images').toggle();
    };

    $scope.user.token = $('#token').val();
    $scope.user.uid = $('#uid').val();


    var credentials = $base64.encode($scope.user.token + ':');

    var carUploader = $scope.carUploader = new FileUploader({
      method: 'POST',
      url: uri('/item/add/images/' + $scope.user.uid + '/' + $scope.itemId),
      headers: {'Authorization': 'Basic ' + credentials},
      autoUpload: true,
      queueLimit: 10
    });

    // filters
    carUploader.filters.push({
      name: 'imageFilter',
      fn: function (item /*{File|FileLikeObject}*/, options) {
        var type = '|' + item.type.slice(item.type.lastIndexOf('/') + 1) + '|';
        return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
      }
    });

    carUploader.onWhenAddingFileFailed = function (item /*{File|FileLikeObject}*/, filter, options) {
      $scope.addedPhoto = false;
      $scope.error = "Error file format";
    };
    carUploader.onAfterAddingFile = function (fileItem) {
      $scope.addedPhoto = true;
    };
    carUploader.onSuccessItem = function (fileItem, response, status, headers) {
      if (response.error) {
        $scope.error = response.error;
      } else {
        console.info("picture", response);
        $scope.car.images = response;
        $scope.addedPhoto = false;
      }
    };

    carUploader.onErrorItem = function (fileItem, response, status, headers) {
      $scope.error = "Error upload a photo";
    };

  });

  // TODO: Email controller
  app.controller('EmailController', function ($window) {
    this.sendEmail = function (email) {
      $window.location.href = 'mailto:' + email;
    };
  });

  // TODO: Description controller
  app.controller('DescriptionController', function () {
    this.showDescription = function () {
      $('.description').toggle();
    };
  });

  // TODO: imageBg directive.
  app.directive('imageBg', function () {
    /**
     * Add background image style to element. Use attrs.image
     */
    return function (scope, element, attrs) {
      element.css({'background-image': 'url(\'' + attrs.imageBg + '\')'});
    }
  });

  // TODO: Image preview
  app.directive('ngThumb', ['$window', function ($window) {
    var helper = {
      support: !!($window.FileReader && $window.CanvasRenderingContext2D),
      isFile: function (item) {
        return angular.isObject(item) && item instanceof $window.File;
      },
      isImage: function (file) {
        var type = '|' + file.type.slice(file.type.lastIndexOf('/') + 1) + '|';
        return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
      }
    };

    return {
      restrict: 'A',
      template: '<canvas class="rounded-circle"><canvas/>',
      link: function (scope, element, attributes) {
        if (!helper.support) return;

        var params = scope.$eval(attributes.ngThumb);

        if (!helper.isFile(params.file)) return;
        if (!helper.isImage(params.file)) return;

        var canvas = element.find('canvas');
        var reader = new FileReader();

        reader.onload = onLoadFile;
        reader.readAsDataURL(params.file);

        function onLoadFile(event) {
          var img = new Image();
          img.onload = onLoadImage;
          img.src = event.target.result;
        }

        function onLoadImage() {
          var width = params.width || this.width / this.height * params.height;
          var height = params.height || this.height / this.width * params.width;
          canvas.attr({width: width, height: height});
          canvas[0].getContext('2d').drawImage(this, 0, 0, width, height);
        }
      }
    };
  }]);

})();

