import { type ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'

const navLinks = [
  { to: '/',        label: 'Audit Trail', end: true },
  { to: '/users',   label: 'Users' },
  { to: '/policies',label: 'Policies' },
  { to: '/evals',   label: 'Evals' },
]

export function Layout({ children }: { children: ReactNode }) {
  const { userID, logout } = useAuth()

  return (
    <div className="min-h-screen bg-gray-100">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">CrabTrap</h1>
              <p className="text-sm text-gray-600">Security-focused HTTP proxy</p>
            </div>
            <div className="flex items-center gap-6">
              {userID && (
                <div className="flex items-center gap-3 text-sm text-gray-600">
                  <span>{userID}</span>
                  <button
                    onClick={logout}
                    className="text-gray-400 hover:text-gray-700 transition-colors text-xs underline"
                  >
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      <nav className="bg-white shadow-sm border-t border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {navLinks.map(({ to, label, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `py-4 px-1 border-b-2 font-medium text-sm ${
                    isActive
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`
                }
              >
                {label}
              </NavLink>
            ))}
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  )
}
