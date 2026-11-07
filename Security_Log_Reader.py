class SecurityEvent:
    
    def __init__(self , ip : str , status : int , response_ms : int | float):
        
        if type(ip) is not str :
            raise TypeError("The Ip must be a string")
        
        if not ip.strip() :
            raise ValueError("the value must be non-empty")
        
        if type(status) is not int :
            raise TypeError("The Status must be an int")
        if not 100 <= status <= 599 :
            raise ValueError("The status should be between 100 and 599")
        
        if type(response_ms) not in (int , float) :
            raise TypeError("The response time must be a numeric")
        if response_ms < 0 :
            raise ValueError("The response time must be not negative")
        
        self.ip = ip
        self.status = status
        self.response_ms = response_ms
    
    def is_error(self) -> bool :
        
        return 400 <= self.status <= 599
        


try:
 Log = SecurityEvent("192.168.1.10" , 500 , 120 )
 print(Log.is_error())
 
except (TypeError , ValueError) as e :
     print(e)
    