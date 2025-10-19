from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.timezone import now
from datetime import timedelta

class Reservation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    spot = models.ForeignKey('ParkingSpot', on_delete=models.CASCADE, related_name="reservations")
    start_time = models.DateField()
    end_time = models.DateField()
    is_paid = models.BooleanField(default=False)  # Track payment status

    def __str__(self):
        return f"Reservation for {self.user.username} at spot {self.spot.spot_number} from {self.start_time} to {self.end_time}"

    @property
    def duration(self):
        if self.start_time and self.end_time:  # Ensure both dates are set
            return (self.end_time - self.start_time).days + 1
        return None  # Return None if either date is missing


    def delete(self, *args, **kwargs):
        # Free the spot on reservation deletion
        if not self.spot.reservations.filter(end_time__gte=now()).exists():
            self.spot.is_reserved = False
            self.spot.save()
        super().delete(*args, **kwargs)
        
    def check_payment_due(self):
        if not self.is_paid and self.payment_due_time and timezone.now() > self.payment_due_time:
            self.delete()  # Cancel reservation if payment is overdue

class ParkingLocation(models.Model):
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=200, blank=True)
    latitude = models.FloatField(null=True, blank=True)  # New field for latitude
    longitude = models.FloatField(null=True, blank=True)  # New field for longitude

    def __str__(self):
        return self.name

class ParkingSpot(models.Model):
    location = models.ForeignKey(
        'ParkingLocation',
        on_delete=models.CASCADE,
        related_name="spots"
    )
    spot_number = models.CharField(max_length=10)
    is_reserved = models.BooleanField(default=False)
    is_rentable = models.BooleanField(default=False)
    daily_price = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        null=True, 
        blank=True
    )
    owner = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='owned_spots'
    )
    is_approved = models.BooleanField(default=False)

    def is_available(self, start_time, end_time):
        """Check if the parking spot is available for a given time period."""
        return not self.reservations.filter(
            start_time__lt=end_time, end_time__gt=start_time
        ).exists()

    def reserve(self, user, start_time, end_time):
        """Reserve a parking spot if available."""
        if self.is_available(start_time, end_time) and self.is_approved:
            reservation = Reservation.objects.create(
                user=user,
                spot=self,
                start_time=start_time,
                end_time=end_time
            )
            self.is_reserved = True
            self.save()
            return reservation
        return None

    def release_if_expired(self):
        """Release the parking spot if no ongoing or future reservations exist."""
        if not self.reservations.filter(end_time__gte=now()).exists():
            self.is_reserved = False
            self.save()

    def __str__(self):
        rentable_status = " (Rentable)" if self.is_rentable else ""
        approval_status = " (Approved)" if self.is_approved else " (Pending Approval)"
        return f"Spot {self.spot_number} at {self.location.name}{rentable_status}{approval_status}"

class Review(models.Model):
    location = models.ForeignKey(ParkingLocation, related_name='reviews', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.IntegerField(choices=[(1, '1'), (2, '2'), (3, '3'), (4, '4'), (5, '5')])
    comment = models.TextField()

    def __str__(self):
        return f'Review by {self.user.username} for {self.location.name}'