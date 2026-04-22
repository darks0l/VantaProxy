import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Parse a datetime-local string (e.g. "2026-01-15T14:30") as local time.
//
// Using `new Date(datetimeLocalString)` is unreliable: strings without seconds
// (the format browsers write for datetime-local inputs) are treated as local
// time in Chrome/Firefox but as UTC in some Safari versions. The multi-argument
// Date constructor is always unambiguously local time in every environment.
export function parseDatetimeLocal(value: string): Date {
  const [datePart = '', timePart = ''] = value.split('T')
  const [year, month, day] = datePart.split('-').map(Number)
  const [hours = 0, minutes = 0] = timePart.split(':').map(Number)
  return new Date(year, month - 1, day, hours, minutes)
}
