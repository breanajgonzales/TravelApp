'use strict';


/* Controllers */

angular.module('roApp.controllers', [])
    .controller('BaseController', ['$scope', '$window', 'brand', 'SessionService', function ($scope, $window, brand, SessionService) {
        $scope.session = SessionService.getSession();
        $scope.brand = brand;

        $scope.doLogout = function () {
            SessionService.removeSession();
            $window.location = '/';
        };
        $scope.$on('event:login-confirmed', function () {
            console.log('event has been broadcast to Home Controller');
            $scope.session = SessionService.getSession();
        });
    }])
    .controller('DragnDropCtrl', function($scope) {
            $scope.image = null
            $scope.imageFileName = ''
        })
    .controller('LoginController', ['$scope', 'SessionService', 'Restangular', function($scope, SessionService, Restangular) {
        $scope.session = SessionService.getSession();
        $scope.user = {};

        $scope.$on('event:login-confirmed', function () {
            console.log('event has been broadcast to Home Controller');
            $scope.session = SessionService.getSession();
        });
    }])
    .controller('RegisterController', ['$scope', '$window', 'Restangular', 'SessionService', function($scope, $window, Restangular, SessionService) {
        $scope.user = {}

        $scope.username = null;
        $scope.password = null;
        $scope.first_name = null;
        $scope.last_name = null;
        $scope.email = null;

        $scope.doRegister = function() {
            $scope.user = {
                'email': $scope.email,
                'password': $scope.password,
                'username': $scope.username,
                'date_joined': new Date(),
                'first_name': $scope.first_name,
                'last_name': $scope.last_name
            };
            Restangular.all('users').customPOST($scope.user)
                .then(function(response) {
                    $window.location = 'index.html#/accountProfile';
                    console.log('Register Success: ' + response);
                }), function(response) {
                    console.log('Register error: ' + response);
                    $scope.errorMessage = response;
                };
        }

        $scope.hasError = function (field, validation) {
            if (validation) {
                return $scope.registerForm[field].$dirty && $scope.registerForm[field].$error[validation];
            }
            return $scope.registerForm[field].$dirty && $scope.registerForm[field].$invalid;
        };
    }])
    .controller('CreateLocationController', ['$scope', '$http', 'SessionService', 'Restangular', '$window', function($scope, $http, SessionService, Restangular, $window) {
        $scope.session = SessionService.getSession();

        $scope.$on('event:login-confirmed', function() {
            console.log('event has been broadcast to Home Controller');
            $scope.session = SessionService.getSession();
        });
        $scope.image = null;
        $scope.imageFileName = '';
        $scope.location = Object();
        $scope.gpsLat = null;
        $scope.gpsLng = null;
        $scope.street = null;
        $scope.city = null;
        $scope.state = null;
        $scope.country = null;
        $scope.locationName = null;
        $scope.description = null;
        $scope.photos = null;
        $scope.comments = "none";
        $scope.sponsored = null;
        $scope.voteCount = 0;
        $scope.submitted = false;
        $scope.reliableGPS = false;

        $scope.uploadFile = function (files) {
            $scope.location.photos = files[0];
            console.log($scope.location.photos);
        };

        var pushToServer = function () {
            var fd = new FormData();
            fd.append("locationName", $scope.locationName);
            fd.append("description", $scope.description);
            fd.append("gpsLng", $scope.gpsLng);
            fd.append("gpsLat", $scope.gpsLat);
            fd.append("reliableGPS", $scope.reliableGPS);
            fd.append("street", $scope.street);
            fd.append("city", $scope.city);
            fd.append("state", $scope.state);
            fd.append("country", $scope.country);
            fd.append("photos", $scope.location.photos);
            fd.append("comments", $scope.comments);
            fd.append("sponsored", $scope.sponsored);
            fd.append("user", $scope.session.id);
            fd.append("voteCount", $scope.voteCount);

            $http.post('http://localhost:8001/location', fd, {
                withCredentials: true,
                headers: {'Content-Type': undefined },
                transformRequest: angular.identity
            }).success(function (response) {
                    $window.location = 'index.html#/home';
                }).error(function (response) {
                    console.log('Response: ' + response);
                });
        };

        $scope.save = function () {
            if ($scope.submitted == false) {
                $scope.reliableGPS = true;

                // Grabs the GPS coordinates if it's not already there --------------------------------------------------------------------------------->
                if ($scope.gpsLat == null || $scope.gpsLng == null){
                    $scope.reliableGPS = false; // determines if the coordinates were manually entered or approximated based on the city
                    var geocoder = new google.maps.Geocoder();
                    var locateMe = $scope.city + ", "+ $scope.state;

                    console.log("Im travelling to: "+locateMe);
                    var geocoderRequest = { address: locateMe };
                    geocoder.geocode(geocoderRequest, function (results, status) {
                        $scope.geoLocater = results;

                        $scope.gpsLng = $scope.geoLocater[0].geometry.location.e;
                        $scope.gpsLat = $scope.geoLocater[0].geometry.location.d;
//                        var myLatlng= new google.maps.LatLng(lat, lng);

                        pushToServer();
                    });
                }  // Ends Maps the Location --------------------------------------------------------------------------------->
                else{
                    pushToServer();
                }
            }
        }

    }])
    .controller('EditLocationController', ['$scope', '$http', 'SessionService', 'Restangular', '$window', '$routeParams', function($scope, $http, SessionService, Restangular, $window, $routeParams) {
        $scope.session = SessionService.getSession();
        console.log($scope.session);

        $scope.$on('event:login-confirmed', function() {
            $scope.session = SessionService.getSession();
        });
        $scope.oldLocationName = '';

        $scope.uploadFile = function (files) {
            $scope.location.photos = files[0];
        };

        var pushToServer = function () {
            var fd = new FormData();
            fd.append("locationName", $scope.location.locationName);
            fd.append("description", $scope.location.description);
            fd.append("gpsLat", $scope.location.gpsLat);
            fd.append("gpsLng", $scope.location.gpsLng);
            fd.append("reliableGPS", $scope.location.reliableGPS);
            fd.append("street", $scope.location.street);
            fd.append("city", $scope.location.city);
            fd.append("state", $scope.location.state);
            fd.append("country", $scope.location.country);
            if ($scope.location.photos.hasOwnProperty('type')) {
                fd.append("photos", $scope.location.photos);
            }
            fd.append("comments", $scope.location.comments);
            fd.append("sponsored", $scope.location.sponsored);
            fd.append("user", $scope.location.user);
            fd.append("voteCount", $scope.location.voteCount);

            var locationUrl = 'http://localhost:8001/location-detail/' + $routeParams.id;
//            var locationUrl = 'http://vast-journey-8108.herokuapp.com/location-detail/' + $routeParams.id;
            $http.put(locationUrl, fd, {
                withCredentials: true,
                headers: {'Content-Type': undefined },
                transformRequest: angular.identity
            }).success(function (response) {
                    $window.location = 'index.html#/locationDetails/' + $scope.location.id;
                }).error(function (response) {
                    console.log('Response: ' + response);
                });
        };

        $scope.update = function () {
            if ($scope.submitted == false) {
                $scope.location.reliableGPS = true;

                // Grabs the GPS coordinates if it's not already there --------------------------------------------------------------------------------->
                if ($scope.location.gpsLat == '' || $scope.location.gpsLng == '' || $scope.location.gpsLat == null || $scope.location.gpsLng == null){
                    $scope.location.reliableGPS = false; // determines if the coordinates were manually entered or approximated based on the city
                    var geocoder = new google.maps.Geocoder();
                    var locateMe = $scope.location.city + ", "+ $scope.location.state + ", " + $scope.location.country;

                    console.log("Im travelling to: "+locateMe);
                    var geocoderRequest = { address: locateMe };
                    geocoder.geocode(geocoderRequest, function (results, status) {
                        $scope.geoLocater = results;

                        $scope.location.gpsLng = $scope.geoLocater[0].geometry.location.e;
                        $scope.location.gpsLat = $scope.geoLocater[0].geometry.location.d;
//                        var myLatlng= new google.maps.LatLng(lat, lng);

                        pushToServer();
                    });
                }  // Ends Maps the Location --------------------------------------------------------------------------------->
                else{
                    pushToServer();
                }
            }
        }


        $scope.session = SessionService.getSession();
        //to display images from Home page
        Restangular.one('uploadedimages', $routeParams.id).customGET()
            .then(function (photo_url) {
                $scope.photo_url = photo_url[0];
        });

        Restangular.one('location-detail', $routeParams.id).customGET()
        .then(function (location) {
          $scope.location = location;
          $scope.oldLocationName = $scope.location.locationName;
        });

        $scope.commentText = null;
        $scope.submitted = false;

        // This saves a Comment
        $scope.save = function () {
            if ($scope.submitted == false) {

                var fd = {};
                fd["locationPostID"] = $routeParams.id;
                fd["commentText"] = $scope.commentText;
                fd["user"] = $scope.session.id;

                $http({
                    method: 'POST',
                    url: 'http://localhost:8001/comment',
                    data: fd
                }).success(function (response) {
                        $scope.commentList[$scope.commentList.length] = response;
                        $scope.submitted = true;
                    }).error(function (response) {
                        console.log("there was an Error! Run!!" + response);
                    });
            }
        };
        $scope.countChoculaUp = function(location){
            if (location.voted==null){
                location.voteCount += 1;
                location.voted = true;
                delete location.photos;
                Restangular.one('location-detail', location.id).customPUT(location)
                .then(function (data) {
                  console.log(data);
                })
            }
        };
        $scope.countChoculaDown = function(location){
            if (location.voted==null){
                location.voteCount -= 1;
                location.voted = true;
                delete location.photos;
                Restangular.one('location-detail', location.id).customPUT(location)
                .then(function (data) {
                  console.log(data);
                })
            }
        };

        $scope.commentList = {};
        Restangular.all('comments-by-location').getList({'locationID':$routeParams.id})
            .then(function (data) {
                $scope.commentList = data;
                console.log("Success! you got data");
                console.log($scope.commentList);
            });

    }])
    .controller('HomeController', ['$scope', 'mapService', 'SessionService', 'Restangular', '$window', '$routeParams', function ($scope, mapService, SessionService, Restangular, $window, $routeParams) {
        $scope.session = SessionService.getSession();

        $scope.user = {};

        $scope.$on('event:login-confirmed', function() {
            console.log('event has been broadcast to Home Controller');
            $scope.session = SessionService.getSession();
        });

        $scope.predicate = '-voteCount';
        $scope.predicate = '-datecreated';

        // allows images to show up on the homepage
        $scope.imagefinder = function () {
            for (var i = 0; i < $scope.locationList.length; i++) {
                Restangular.one('uploadedimages', $scope.locationList[i].id).customGET()
                    .then(function (photo_url) {
                        for (var j = 0; j < $scope.locationList.length; j++) {
                            if ($scope.locationList[j].id == photo_url[1]) {
                                $scope.locationList[j].photo_url = photo_url[0];
                            }
                        }
                    });
            }
        };

        $scope.locationList = {};
        Restangular.all('location').getList()
            .then(function (data) {
                if ($routeParams.hasOwnProperty('starred')) {
                   $scope.locationList = [];
                    for (var i =0; i<data.length; i++){
                       if(data[i].starLocation){
                           $scope.locationList.push(data[i]);
                       }
                   }
                }
                else {
                    $scope.locationList = data;
                }
                $scope.imagefinder();
                mapService.main($scope.locationList);
        });

        // Saves the Up Votes and down Votes back to the server
        var vote = false;

        $scope.countChoculaUp = function(location){
            if (location.voted==null){
                location.voteCount += 1;
                location.voted = true;
                delete location.photos;
                Restangular.one('location-detail', location.id).customPUT(location)
                .then(function (data) {
                })
            }
        };
        $scope.countChoculaDown = function(location){
            if (location.voted==null){
                location.voteCount -= 1;
                location.voted = true;
                delete location.photos;
                Restangular.one('location-detail', location.id).customPUT(location)
                .then(function (data) {
                })
            }
        };

        $scope.starLocation = function(location){
            location.starLocation = !location.starLocation;
            delete location.photos;
            Restangular.one('location-detail', location.id).customPUT(location)
                .then(function (data) {
                    $scope.location.starLocation = data.starLocation;
                })
        };

        $scope.userList = {};
        Restangular.all('users').getList()
            .then(function (data) {
                $scope.userList = data;
            })
    }])
    .controller('AccountProfileController', ['$scope', 'SessionService', 'Restangular', function($scope, SessionService, Restangular) {
        $scope.session = SessionService.getSession();
        $scope.currentUserInfo = SessionService.getSession();

        $scope.myLocationList = [];
        if (SessionService.getUserLocations()){
            $scope.myLocationList=SessionService.getUserLocations();
        }

        $scope.$on('event:login-confirmed', function() {
            console.log('event has been broadcast to Home Controller');
            $scope.session = SessionService.getSession();

            Restangular.all('location').getList()
            .then(function (data) {
                $scope.locationList = data;
//
//                if ($scope.session.is_superuser == true || $scope.location.user == $scope.session.id){
//                    $scope.showEdit = "Approved";
//                    }
//                    else{
//                    $scope.showEdit = null;
//                    }
//                if ($scope.location.reliableGPS == false){
//                    $scope.gpsStatus = "These coordinates have been approximated to the city center";
//                    }
//                    else{
//                        $scope.gpsStatus = "These coordinates have been manually entered and should be exact";
//                    }
//
                for (var i = 0; i < $scope.locationList.length; i++){
                    if ($scope.locationList[i].user==$scope.session.id){
                        $scope.myLocationList.push($scope.locationList[i]);
                        console.log($scope.myLocationList);
                    }
                }
                SessionService.saveUserLocations($scope.myLocationList);
            })
        });
    }])

    .controller('LocationDetailsController', ['$scope', '$http', 'SessionService', 'Restangular', '$routeParams', function ($scope, $http, SessionService, Restangular, $routeParams) {
        $scope.session = SessionService.getSession();
        //to display images from Home page

        Restangular.one('uploadedimages', $routeParams.id).customGET()
            .then(function (photo_url) {
                $scope.photo_url = photo_url[0];
        });

        Restangular.one('location-detail', $routeParams.id).customGET()
        .then(function (location) {
            $scope.location = location;

            if ($scope.session.is_superuser == true || $scope.location.user == $scope.session.id){
                $scope.showEdit = "Approved";
                }
                else{
                $scope.showEdit = null;
                }
            if ($scope.location.reliableGPS == false){
                $scope.gpsStatus = "These coordinates have been approximated to the city center";
                }
                else{
                    $scope.gpsStatus = "These coordinates have been manually entered and should be exact";
                }

            // Maps the Location --------------------------------------------------------------------------------->
            var myLatlng = new google.maps.LatLng($scope.location.gpsLat, $scope.location.gpsLng);
            var mapOptions = {
                zoom: 6,
                center: myLatlng
            };
            var map = new google.maps.Map(document.getElementById('map-canvas'), mapOptions);

            var marker = new google.maps.Marker({
                position: myLatlng,
                map: map,
                title: $scope.location.locationName
            });
            // Ends Maps the Location --------------------------------------------------------------------------------->
        });

        $scope.commentText = null;
        $scope.submitted = false;

        $scope.save = function () {
            if ($scope.submitted == false) {

                var fd = {};
                fd["locationPostID"] = $routeParams.id;
                fd["commentText"] = $scope.commentText;
                fd["user"] = $scope.session.id;

                $http({
                    method: 'POST',
                    url: 'http://localhost:8001/comment',
                    data: fd
                }).success(function (response) {
                        $scope.commentList[$scope.commentList.length] = response;
                        $scope.submitted = true;
                    }).error(function (response) {
                        console.log("there was an Error! Run!!" + response);
                    });
            }
        };
        //to save upvotes and downvotes to server

        $scope.countChoculaUp = function(location){
            if (location.voted==null){
                location.voteCount += 1;
                location.voted = true;
                delete location.photos;
                Restangular.one('location-detail', location.id).customPUT(location)
                    .then(function (data) {
                })
            }
        };
        $scope.countChoculaDown = function(location){
            if (location.voted==null){
                location.voteCount -= 1;
                location.voted = true;
                delete location.photos;
                Restangular.one('location-detail', location.id).customPUT(location)
                    .then(function (data) {
                })
            }
        };
        $scope.starLocation = function(location){
            location.starLocation = !location.starLocation;
            delete location.photos;
            Restangular.one('location-detail', location.id).customPUT(location)
                .then(function (data) {
                    $scope.location.starLocation = data.starLocation;
                })
        };
        $scope.commentList = {};
        Restangular.all('comments-by-location').getList({'locationID':$routeParams.id})
            .then(function (data) {
                $scope.commentList = data;
            });
    }]);


