# Tarpaulin-Course-Management-API
RESTful API for an application called Tarpaulin, a lightweight course management tool. The API will be deployed on Google Cloud Platform using Google App Engine and Datastore, using Python 3. Auth0 will be used for authentication.

# Functionality
The Tarpaulin REST API has 13 endpoints, most of which are protected. The protected endpoints require a valid JWT in the request as Bearer token in the Authorization header. Each user in Tarpaulin has one of three roles: admin, instructor, and student.

This documentation provides an overview of the API endpoints, their functionality, and the required permissions.

User Endpoints
1. User Login
Endpoint: POST /users/login
Protection: Pre-created Auth0 users with username and password
Description: Use Auth0 to issue JWTs. Minor changes are needed in the response from the example app presented in "Exploration - Implementing Auth Using JWTs."
2. Get All Users
Endpoint: GET /users
Protection: Admin only
Description: Provides summary information of all 9 users. No information about avatar or courses.
3. Get a User
Endpoint: GET /users/:id
Protection: Admin or user with JWT matching id
Description: Provides detailed information about the user, including avatar (if any) and courses (for instructors and students).
4. Create/Update a User’s Avatar
Endpoint: POST /users/:id/avatar
Protection: User with JWT matching id
Description: Allows users to upload their avatar file to Google Cloud Storage.
5. Get a User’s Avatar
Endpoint: GET /users/:id/avatar
Protection: User with JWT matching id
Description: Reads and returns the avatar file from Google Cloud Storage.
6. Delete a User’s Avatar
Endpoint: DELETE /users/:id/avatar
Protection: User with JWT matching id
Description: Deletes the avatar file from Google Cloud Storage.
Course Endpoints
7. Create a Course
Endpoint: POST /courses
Protection: Admin only
Description: Allows admins to create a new course.
8. Get All Courses
Endpoint: GET /courses
Protection: Unprotected
Description: Provides a paginated list of courses using offset/limit. Page size is 3, ordered by “subject.” Does not return information on course enrollment.
9. Get a Course
Endpoint: GET /course/:id
Protection: Unprotected
Description: Provides information about a specific course. Does not return information on course enrollment.
10. Update a Course
Endpoint: PATCH /course/:id
Protection: Admin only
Description: Allows partial updates to a course.
11. Delete a Course
Endpoint: DELETE /course/:id
Protection: Admin only
Description: Deletes a course and its enrollment information.
12. Update Enrollment in a Course
Endpoint: PATCH /courses/:id/students
Protection: Admin or instructor of the course
Description: Allows admins or instructors to enroll or disenroll students from a course.
13. Get Enrollment for a Course
Endpoint: GET /courses/:id/students
Protection: Admin or instructor of the course
Description: Provides a list of all students enrolled in the course.
