class ApiResponse{
    constructor(statusCode,dta,message="Success"){
        this.statusCode=statusCode
        this.data=data 
        this.message=message
        this.success=statusCode<400
    }
}

export {ApiResponse}