'use strict';


/* Controllers */

angular.module('roApp.controllers', [])
    .controller('BaseController', ['$scope', '$window', 'brand', 'SessionService', function ($scope, $window, brand, SessionService) {
        $scope.brand = brand;

        $scope.doLogout = function () {
            SessionService.removeSession();
            $window.location = '/';
        };
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
                .then(function(data) {
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
        Restangular.one('getuserid',$scope.session).get()
        .then(function(data) {
            $scope.user = data;
        });

        $scope.$on('event:login-confirmed', function() {
            console.log('event has been broadcast to Home Controller');
            $scope.session = SessionService.getSession();
        });
        $scope.image = null;
        $scope.imageFileName = '';
        $scope.location = Object();
        $scope.gps = null;
        $scope.street = null;
        $scope.city = null;
        $scope.state = null;
        $scope.country = null;
        $scope.locationName = null;
        $scope.description = null;
        $scope.photos = null;
        $scope.comments = "none";
        $scope.sponsored = null;
        $scope.upVoteCount = 0;
        $scope.downVoteCount = 0;
        $scope.submitted = false;

        $scope.uploadFile = function (files) {
            $scope.location.photos = files[0];
            console.log($scope.location.photos);
        }
        $scope.save = function () {
            if ($scope.submitted == false) {
                var fd = new FormData();
                fd.append("locationName", $scope.locationName);
                fd.append("description", $scope.description);
                fd.append("gps", $scope.gps);
                fd.append("street", $scope.street);
                fd.append("city", $scope.city);
                fd.append("state", $scope.state);
                fd.append("country", $scope.country);
                fd.append("photos", $scope.location.photos);
                fd.append("comments", $scope.comments);
                fd.append("sponsored", $scope.sponsored);
                fd.append("user", $scope.user);
                fd.append("upVoteCount", $scope.upVoteCount);
                fd.append("downVoteCount", $scope.downVoteCount);

                $http.post('http://localhost:8001/location', fd, {
//                   withCredentials: true,
                    headers: {'Content-Type': undefined },
                    transformRequest: angular.identity
                }).success(function (response) {
                        $window.location = 'index.html#/home';
                    }).error(function (response) {
                        console.log('Response: ' + response);
                    });
            }
        }

    }])
    .controller('HomeController', ['$scope', 'SessionService', 'Restangular', function ($scope, SessionService, Restangular) {
        $scope.session = SessionService.getSession();

        $scope.user = {};

        $scope.$on('event:login-confirmed', function() {
            console.log('event has been broadcast to Home Controller');
            $scope.session = SessionService.getSession();
        });
        var s = $(".filterbox");
        var pos = s.position();
        $(window).scroll(function() {
            var windowpos = $(window).scrollTop();
            if (windowpos >= pos.top-40) {
                s.addClass("stick");
            } else {
                s.removeClass("stick");
            }
        });
        // for the filters / sorting functionality
        $scope.predicate = '-upVoteCount';
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
        }

        $scope.locationList = {};
        Restangular.all('location').getList()
            .then(function (data) {
                $scope.locationList = data;
                $scope.imagefinder();
            })

        // Saves the Up Votes and down Votes back to the server
        var vote = false;

        $scope.countChoculaUp = function(location){
            if (location.voted==null){
                location.upVoteCount += 1;
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
                location.downVoteCount -= 1;
                location.voted = true;
                delete location.photos;
                Restangular.one('location-detail', location.id).customPUT(location)
                .then(function (data) {
                  console.log(data);
                })
            }
        };

        $scope.userList = {};
        Restangular.all('users').getList()
            .then(function (data) {
                $scope.userList = data;
            })
    }])
    .controller('AccountProfileController', ['$scope', 'SessionService', 'Restangular', function($scope, SessionService, Restangular) {
        $scope.session = SessionService.getSession();
//        $scope.currentUserInfo = SessionService.getUserSession();
        $scope.myLocationList = [];
        $scope.locationList = {};

        Restangular.one('getuserid',$scope.session).get()
        .then(function(data) {
            $scope.userId = data;
            Restangular.one('users',$scope.userId).get()
            .then(function(data) {
                $scope.user = data;
            });
            Restangular.all('location').getList()
            .then(function (data) {
                $scope.locationList = data;
                for (var i = 0; i < $scope.locationList.length; i++){
                    if ($scope.locationList[i].user==$scope.userId){
                        $scope.myLocationList.push($scope.locationList[i]);
                        console.log($scope.myLocationList);
//                fd.append("locationName", $scope.locationName);
                    }
                }
//          $scope.imagefinder();
            })
        });

        $scope.$on('event:login-confirmed', function() {
            console.log('event has been broadcast to Home Controller');
            $scope.session = SessionService.getSession();
        });


//        $scope.userList = {};
//        Restangular.all('users').getList()
//            .then(function(data) {
//                $scope.userList = data;
//                console.log("Success! you got data");
//                console.log($scope.userList);
//            })

    }])

    .controller('LocationDetailsController', ['$scope', '$http', 'SessionService', 'Restangular', '$routeParams', function ($scope, $http, SessionService, Restangular, $routeParams) {
        $scope.session = SessionService.getSession();
        $scope.id = $routeParams.id-1;
        //to display images from Home page
        Restangular.one('uploadedimages', $routeParams.id).customGET()
            .then(function (photo_url) {
                $scope.photo_url = photo_url[0];
        })


        Restangular.all('location').getList()
            .then(function (locationList) {
                $scope.location = locationList[$scope.id];
            });
//
//        SessionService.success(function(data) {
//            $scope.locationList = data;
//            $scope.location = $scope.locationList[$scope.id];
//            })
        $scope.comment = Object();
        $scope.locationPostID = $scope.id;
        $scope.commentText = null;
        $scope.submitted = false;
        $scope.user = 1;

//        console.log('USER: ' + JSON.stringify($scope.session));

        $scope.save = function () {
            if ($scope.submitted == false) {
                $scope.comment.locationPostID = $scope.locationPostID;
                $scope.comment.commentText = $scope.commentText;
                $scope.comment.user = $scope.user;

                var fd = {};
                fd["locationPostID"] = $scope.comment.locationPostID+1;
                fd["commentText"] = $scope.comment.commentText;
                fd["user"] = $scope.comment.user;

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
        var vote = false;


        $scope.countChoculaUp = function(location){
            if (location.voted==null){
                location.upVoteCount += 1;
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
                location.downVoteCount -= 1;
                location.voted = true;
                delete location.photos;
                Restangular.one('location-detail', location.id).customPUT(location)
                .then(function (data) {
                  console.log(data);
                })
            }
        };

        $scope.commentList = {};
        Restangular.all('comments-by-location').getList({'locationID':$scope.locationPostID+1})
            .then(function (data) {
                $scope.commentList = data;
                console.log("Success! you got data");
                console.log($scope.commentList);
            })
        $scope.userList = {};
        Restangular.all('users').getList()
            .then(function (data) {
                $scope.userList = data;
            })
    }]);


