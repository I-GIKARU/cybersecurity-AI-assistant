from typing import List
from datetime import datetime
from pydantic import BaseModel

class Appointment(BaseModel):
    id: str
    patient_name: str
    patient_email: str = ""
    doctor: str
    appointment_type: str
    date: datetime
    duration: int = 30
    status: str = "scheduled"
    notes: str = ""

class AppointmentStorage:
    _instance = None
    _appointments: List[Appointment] = []
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AppointmentStorage, cls).__new__(cls)
        return cls._instance
    
    def add_appointment(self, appointment: Appointment) -> str:
        self._appointments.append(appointment)
        return appointment.id
    
    def get_appointments(self, patient_name: str = None, status: str = "scheduled") -> List[Appointment]:
        if patient_name:
            return [apt for apt in self._appointments 
                   if apt.patient_name.lower() == patient_name.lower() and apt.status == status]
        return [apt for apt in self._appointments if apt.status == status]
    
    def get_appointment_by_id(self, appointment_id: str) -> Appointment:
        for apt in self._appointments:
            if apt.id == appointment_id:
                return apt
        return None
    
    def cancel_appointment(self, appointment_id: str) -> bool:
        apt = self.get_appointment_by_id(appointment_id)
        if apt:
            apt.status = "cancelled"
            return True
        return False
    
    def is_slot_available(self, slot_time: datetime, doctor: str) -> bool:
        for apt in self._appointments:
            if (apt.doctor == doctor and 
                apt.date.date() == slot_time.date() and
                apt.date.hour == slot_time.hour and
                apt.date.minute == slot_time.minute and
                apt.status == "scheduled"):
                return False
        return True
    
    def get_next_appointment_id(self) -> str:
        return f"APT-{len(self._appointments) + 1:04d}"
