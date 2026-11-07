from dataclasses import dataclass

@dataclass
class SecurityEvent:
    
    ip : str
    status : int
    response_ms : int | float
    
    def __post_init__(self):
        
        if type(self.ip) is not str :
            raise TypeError("The Ip must be a string")
        
        if not self.ip.strip() :
            raise ValueError("the value must be non-empty")
        
        if type(self.status) is not int :
            raise TypeError("The Status must be an int")
        if not 100 <= self.status <= 599 :
            raise ValueError("The status should be between 100 and 599")
        
        if type(self.response_ms) not in (int , float) :
            raise TypeError("The response time must be a numeric")
        if self.response_ms < 0 :
            raise ValueError("The response time must be not negative")
    
    def is_error(self) -> bool :
        
        return 400 <= self.status <= 599
        


try:
 Log = SecurityEvent("192.168.1.10" , 500 , 120 )
 print(Log.is_error())
 
except (TypeError , ValueError) as e :
     print(e)
    